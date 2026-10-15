/*
Copyright (c) 2025 Jørgen Lind

  Permission is hereby granted, free of charge, to any person obtaining a copy of
  this software and associated documentation files (the "Software"), to deal in
  the Software without restriction, including without limitation the rights to
  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
  of the Software, and to permit persons to whom the Software is furnished to do
  so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

#include <algorithm>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/ref_counted_wrapper.h>

namespace
{
using log_t = std::vector<std::string>;

class probe_t final : public vio::detail::resource_t
{
public:
  probe_t(vio::event_loop_t &loop, log_t &log, std::string name, bool hold = false)
    : resource_t(vio::detail::core(loop), "probe")
    , _log(log)
    , _name(std::move(name))
    , _hold(hold)
  {
  }

  void finish() noexcept
  {
    _log.push_back("finish " + _name);
    close_finished();
  }

private:
  void do_close() noexcept override
  {
    _log.push_back("close " + _name);
    if (!_hold)
      close_finished();
  }

  log_t &_log;
  std::string _name;
  bool _hold;
};

struct single_t
{
  log_t &log;
  probe_t probe;

  single_t(vio::event_loop_t &loop, log_t &log, bool hold = false)
    : log(log)
    , probe(loop, log, "a", hold)
  {
  }
  single_t(const single_t &) = delete;
  single_t &operator=(const single_t &) = delete;
  single_t(single_t &&) = delete;
  single_t &operator=(single_t &&) = delete;
  ~single_t()
  {
    log.push_back("freed");
  }
};

struct triple_t
{
  log_t &log;
  probe_t a;
  probe_t b;
  probe_t c;

  triple_t(vio::event_loop_t &loop, log_t &log, bool hold_b = false)
    : log(log)
    , a(loop, log, "a")
    , b(loop, log, "b", hold_b)
    , c(loop, log, "c")
  {
  }
  triple_t(const triple_t &) = delete;
  triple_t &operator=(const triple_t &) = delete;
  triple_t(triple_t &&) = delete;
  triple_t &operator=(triple_t &&) = delete;
  ~triple_t()
  {
    log.push_back("freed");
  }
};

struct signal_t
{
  vio::detail::loop_core_t &core;
  vio::detail::posted_t node;
  probe_t probe;
  std::function<void()> callback;
  bool &freed;

  signal_t(vio::event_loop_t &loop, log_t &log, std::function<void()> callback, bool &freed)
    : core(vio::detail::core(loop))
    , probe(loop, log, "signal")
    , callback(std::move(callback))
    , freed(freed)
  {
    node.owner = this;
    node.run = [](vio::detail::posted_t *posted) { static_cast<signal_t *>(posted->owner)->callback(); };
  }
  signal_t(const signal_t &) = delete;
  signal_t &operator=(const signal_t &) = delete;
  signal_t(signal_t &&) = delete;
  signal_t &operator=(signal_t &&) = delete;
  ~signal_t()
  {
    core.unpost(node);
    freed = true;
  }

  void send()
  {
    core.post(node);
  }
};

bool contains(const log_t &log, const std::string &entry)
{
  return std::ranges::find(log, entry) != log.end();
}

TEST_SUITE("Handle Closer")
{
  TEST_CASE("an object may drop its own last reference inside its own callback")
  {
    vio::event_loop_t loop;
    log_t log;
    bool freed = false;
    bool freed_inside_callback = true;
    int calls = 0;
    std::function<void()> on_signal;
    vio::ref_ptr_t<signal_t> signal(loop, log, [&on_signal] { on_signal(); }, freed);
    signal.register_resource(signal->probe);
    on_signal = [&] {
      ++calls;
      signal.release();
      freed_inside_callback = freed;
      loop.stop();
    };

    loop.run_in_loop([&] { signal->send(); });
    loop.run();

    CHECK(calls == 1);
    CHECK_FALSE(freed_inside_callback);
    CHECK(freed);
    CHECK(log == log_t{"close signal"});
    CHECK(vio::detail::core(loop).open_resources() == 0);
  }

  TEST_CASE("a signal sent many times before it runs runs once")
  {
    vio::event_loop_t loop;
    log_t log;
    bool freed = false;
    int calls = 0;
    std::optional<vio::ref_ptr_t<signal_t>> signal;
    signal.emplace(loop, log, [&calls] { ++calls; }, freed);
    (*signal).register_resource((*signal)->probe);

    loop.run_in_loop([&] {
      for (int i = 0; i < 5; ++i)
        (*signal)->send();
      loop.run_in_loop([&] {
        signal.reset();
        loop.stop();
      });
    });
    loop.run();

    CHECK(calls == 1);
    CHECK(freed);
  }

  TEST_CASE("a wrapper with a resource can be copied and shared")
  {
    vio::event_loop_t loop;
    log_t log;
    vio::ref_ptr_t<single_t> first(loop, log);
    first.register_resource(first->probe);
    CHECK(first.ref_counted()->ref_count == 1);

    vio::ref_ptr_t<single_t> second = first;
    CHECK(first.ref_counted()->ref_count == 2);
    CHECK(second.ref_counted()->ref_count == 2);
    CHECK(&first.data() == &second.data());

    loop.run_in_loop([&] {
      first.release();
      CHECK(second.ref_counted()->ref_count == 1);
      CHECK(log.empty());
      second.release();
      CHECK(log == log_t{"close a"});
      loop.stop();
    });
    loop.run();

    CHECK(log == log_t{"close a", "freed"});
  }

  TEST_CASE("dropping the last reference outside the loop closes on the next run")
  {
    vio::event_loop_t loop;
    log_t log;
    bool destroyed = false;
    {
      vio::ref_ptr_t<single_t> first(loop, log);
      first.register_resource(first->probe);
      first.on_destroy([&] { destroyed = true; });
      {
        const vio::ref_ptr_t<single_t> second = first;
        const vio::ref_ptr_t<single_t> third = second;
        CHECK(first.ref_counted()->ref_count == 3);
        CHECK_FALSE(destroyed);
      }
      CHECK(first.ref_counted()->ref_count == 1);
      CHECK_FALSE(destroyed);
    }

    CHECK(destroyed);
    CHECK(log == log_t{"close a"});
    CHECK(vio::detail::core(loop).open_resources() == 1);

    loop.stop();
    loop.run();

    CHECK(log == log_t{"close a", "freed"});
    CHECK(vio::detail::core(loop).open_resources() == 0);
  }

  TEST_CASE("a close finishes on a later turn, never inside the call that closed")
  {
    vio::event_loop_t loop;
    log_t log;
    std::optional<vio::ref_ptr_t<single_t>> wrapper;
    wrapper.emplace(loop, log);
    (*wrapper).register_resource((*wrapper)->probe);
    bool freed_in_same_call = true;
    bool freed_on_later_turn = false;

    loop.run_in_loop([&] {
      wrapper.reset();
      freed_in_same_call = contains(log, "freed");
      loop.run_in_loop([&] {
        freed_on_later_turn = contains(log, "freed");
        loop.stop();
      });
    });
    loop.run();

    CHECK_FALSE(freed_in_same_call);
    CHECK(freed_on_later_turn);
  }

  TEST_CASE("destroy callbacks run in reverse, before any resource closes, and resources close in reverse")
  {
    vio::event_loop_t loop;
    log_t log;
    {
      vio::ref_ptr_t<triple_t> wrapper(loop, log);
      wrapper.register_resource(wrapper->a);
      wrapper.register_resource(wrapper->b);
      wrapper.register_resource(wrapper->c);
      wrapper.on_destroy([&log] { log.push_back("destroy 1"); });
      wrapper.on_destroy([&log] { log.push_back("destroy 2"); });
      wrapper.on_destroy([&log] { log.push_back("destroy 3"); });
      CHECK(log.empty());
    }
    CHECK(log == log_t{"destroy 3", "destroy 2", "destroy 1", "close c", "close b", "close a"});

    loop.stop();
    loop.run();

    CHECK(log == log_t{"destroy 3", "destroy 2", "destroy 1", "close c", "close b", "close a", "freed"});
  }

  TEST_CASE("storage is freed only after every resource has closed")
  {
    vio::event_loop_t loop;
    auto &core = vio::detail::core(loop);
    log_t log;
    std::optional<vio::ref_ptr_t<triple_t>> wrapper;
    wrapper.emplace(loop, log, true);
    (*wrapper).register_resource((*wrapper)->a);
    (*wrapper).register_resource((*wrapper)->b);
    (*wrapper).register_resource((*wrapper)->c);
    probe_t *held = &(*wrapper)->b;
    CHECK(core.open_resources() == 3);

    std::size_t open_while_held = 0;
    bool freed_while_held = true;
    bool freed_right_after_finish = true;
    loop.run_in_loop([&] {
      wrapper.reset();
      loop.run_in_loop([&] {
        open_while_held = core.open_resources();
        freed_while_held = contains(log, "freed");
        held->finish();
        freed_right_after_finish = contains(log, "freed");
        loop.stop();
      });
    });
    loop.run();

    CHECK(open_while_held == 1);
    CHECK_FALSE(freed_while_held);
    CHECK_FALSE(freed_right_after_finish);
    CHECK(log == log_t{"close c", "close b", "close a", "finish b", "freed"});
    CHECK(core.open_resources() == 0);
  }

  TEST_CASE("a held close keeps a stopped loop running until it finishes")
  {
    vio::event_loop_t loop;
    log_t log;
    std::optional<vio::ref_ptr_t<single_t>> wrapper;
    wrapper.emplace(loop, log, true);
    (*wrapper).register_resource((*wrapper)->probe);
    probe_t *held = &(*wrapper)->probe;

    vio::thread_with_event_loop_t finisher;
    loop.run_in_loop([&] {
      loop.stop();
      wrapper.reset();
      finisher.event_loop().run_in_loop([&loop, held] { loop.run_in_loop([held] { held->finish(); }); });
    });
    loop.run();
    finisher.stop_and_join();

    CHECK(log == log_t{"close a", "finish a", "freed"});
    CHECK(vio::detail::core(loop).open_resources() == 0);
  }

  TEST_CASE("a parked reference defers closing and freeing until it is released")
  {
    vio::event_loop_t loop;
    log_t log;
    std::optional<vio::ref_ptr_t<single_t>> wrapper;
    wrapper.emplace(loop, log);
    (*wrapper).register_resource((*wrapper)->probe);
    vio::reference_counted_t *counted = (*wrapper).ref_counted();
    (*wrapper).on_destroy([&] {
      log.push_back("park");
      counted->inc();
      loop.run_in_loop([&] {
        log.push_back("unpark");
        counted->dec();
      });
    });

    loop.run_in_loop([&] {
      wrapper.reset();
      CHECK(log == log_t{"park"});
      loop.stop();
    });
    loop.run();

    CHECK(log == log_t{"park", "unpark", "close a", "freed"});
  }

  TEST_CASE("a destroy callback that takes and drops a reference at once does not restart destruction")
  {
    vio::event_loop_t loop;
    log_t log;
    int destroy_calls = 0;
    {
      vio::ref_ptr_t<single_t> wrapper(loop, log);
      wrapper.register_resource(wrapper->probe);
      vio::reference_counted_t *counted = wrapper.ref_counted();
      wrapper.on_destroy([&destroy_calls, counted] {
        ++destroy_calls;
        counted->inc();
        CHECK_FALSE(counted->dec());
      });
    }
    CHECK(destroy_calls == 1);
    CHECK(log == log_t{"close a"});

    loop.stop();
    loop.run();

    CHECK(destroy_calls == 1);
    CHECK(log == log_t{"close a", "freed"});
  }

  TEST_CASE("independent wrappers with nested lifetimes all close and free")
  {
    vio::event_loop_t loop;
    log_t log_1;
    log_t log_2;
    log_t log_3;
    std::vector<int> destroy_order;
    {
      vio::ref_ptr_t<single_t> first(loop, log_1);
      first.register_resource(first->probe);
      first.on_destroy([&destroy_order] { destroy_order.push_back(1); });
      {
        vio::ref_ptr_t<single_t> second(loop, log_2);
        second.register_resource(second->probe);
        second.on_destroy([&destroy_order] { destroy_order.push_back(2); });
        vio::ref_ptr_t<single_t> third(loop, log_3);
        third.register_resource(third->probe);
        third.on_destroy([&destroy_order] { destroy_order.push_back(3); });
      }
      CHECK(destroy_order == std::vector<int>{3, 2});
    }
    CHECK(destroy_order == std::vector<int>{3, 2, 1});
    CHECK(vio::detail::core(loop).open_resources() == 3);

    loop.stop();
    loop.run();

    CHECK(log_1 == log_t{"close a", "freed"});
    CHECK(log_2 == log_t{"close a", "freed"});
    CHECK(log_3 == log_t{"close a", "freed"});
    CHECK(vio::detail::core(loop).open_resources() == 0);
  }

  TEST_CASE("a wrapper with no resource is freed at once")
  {
    log_t log;
    struct plain_t
    {
      log_t &log;
      explicit plain_t(log_t &log)
        : log(log)
      {
      }
      plain_t(const plain_t &) = delete;
      plain_t &operator=(const plain_t &) = delete;
      plain_t(plain_t &&) = delete;
      plain_t &operator=(plain_t &&) = delete;
      ~plain_t()
      {
        log.push_back("freed");
      }
    };
    {
      vio::ref_ptr_t<plain_t> wrapper(log);
      wrapper.on_destroy([&log] { log.push_back("destroy"); });
    }
    CHECK(log == log_t{"destroy", "freed"});
  }
}
} // namespace
