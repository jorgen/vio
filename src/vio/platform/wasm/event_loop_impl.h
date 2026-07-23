#pragma once

#include "vio/about_to_block.h"
#include "vio/task.h"

#include <algorithm>
#include <cassert>
#include <functional>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include <emscripten.h>
#include <emscripten/eventloop.h> // emscripten_set_timeout / emscripten_clear_timeout

namespace vio
{

class event_loop_t
{
public:
  using timer_id_t = int;

  event_loop_t() = default;

  event_loop_t(const event_loop_t &) = delete;
  event_loop_t &operator=(const event_loop_t &) = delete;
  event_loop_t(event_loop_t &&) = delete;
  event_loop_t &operator=(event_loop_t &&) = delete;

  ~event_loop_t()
  {
    for (auto &[id, data] : _active_timers)
    {
      emscripten_clear_timeout(id);
      delete data;
    }
    _active_timers.clear();
  }

  void run_in_loop(std::function<void()> &&event)
  {
    _pending.push_back(std::move(event));
  }

  template <typename F>
    requires std::is_same_v<std::invoke_result_t<F>, task_t<void>>
  void run_in_loop(F &&f)
  {
    _pending.push_back(
      [func = std::forward<F>(f)]() mutable
      {
        [](task_t<void> t) -> detached_task_t { co_await std::move(t); }(func());
      });
  }

  void run()
  {
    drain_pending();
    emscripten_set_main_loop_arg(&tick_cb, this, 0, 0);
  }

  void stop()
  {
    emscripten_cancel_main_loop();
  }

  // Pump this loop once: run everything queued via run_in_loop and fire about-to-block listeners. Used
  // by the cooperative driver (vio::wasm::pump) to multiplex several logical loops onto the single
  // browser main loop, so code written against thread_with_event_loop_t runs unchanged single-threaded.
  void poll()
  {
    tick();
  }

  [[nodiscard]] bool has_pending() const
  {
    return !_pending.empty();
  }

  void add_about_to_block_listener(about_to_block_t *listener)
  {
    _about_to_block_listeners.push_back(listener);
  }

  void remove_about_to_block_listener(about_to_block_t *listener)
  {
    _about_to_block_listeners.erase(std::remove(_about_to_block_listeners.begin(), _about_to_block_listeners.end(), listener), _about_to_block_listeners.end());
  }

  struct timer_data_t
  {
    event_loop_t *loop;
    std::function<void()> callback;
    timer_id_t id;
  };

  timer_id_t add_timer(double delay_ms, std::function<void()> callback)
  {
    auto *data = new timer_data_t{this, std::move(callback), 0};
    auto id = emscripten_set_timeout(&timer_fire_cb, delay_ms, data);
    data->id = id;
    _active_timers[id] = data;
    return id;
  }

  void cancel_timer(timer_id_t id)
  {
    emscripten_clear_timeout(id);
    auto it = _active_timers.find(id);
    if (it != _active_timers.end())
    {
      delete it->second;
      _active_timers.erase(it);
    }
  }

private:
  void drain_pending()
  {
    while (!_pending.empty())
    {
      auto batch = std::move(_pending);
      _pending.clear();
      for (auto &fn : batch)
      {
        fn();
      }
    }
  }

  void tick()
  {
    drain_pending();
    for (auto *listener : _about_to_block_listeners)
    {
      listener->about_to_block();
    }
  }

  static void tick_cb(void *arg)
  {
    static_cast<event_loop_t *>(arg)->tick();
  }

  static void timer_fire_cb(void *arg)
  {
    auto *data = static_cast<timer_data_t *>(arg);
    auto *loop = data->loop;
    auto id = data->id;
    auto callback = std::move(data->callback);
    loop->_active_timers.erase(id);
    delete data;
    callback();
  }

  std::vector<std::function<void()>> _pending;
  std::vector<about_to_block_t *> _about_to_block_listeners;
  std::unordered_map<timer_id_t, timer_data_t *> _active_timers;
};

// Cooperative multi-loop driver. The browser allows exactly one emscripten_set_main_loop, but points'
// design runs several logical event loops (one per subsystem). Each thread_with_event_loop_t registers
// its loop here instead of spawning a thread + calling run(); a single main-loop callback pumps them
// all every frame. This is what lets the multi-thread-shaped design run unchanged on one browser thread
// -- only genuinely blocking (condition_variable) waits, which no cooperative scheduler can satisfy,
// need converting to co_await.
namespace wasm
{
inline std::vector<event_loop_t *> &cooperative_loops()
{
  static std::vector<event_loop_t *> loops;
  return loops;
}

inline std::function<void()> &cooperative_frame_hook()
{
  static std::function<void()> hook;
  return hook;
}

inline void register_loop(event_loop_t *loop)
{
  cooperative_loops().push_back(loop);
}

inline void unregister_loop(event_loop_t *loop)
{
  auto &loops = cooperative_loops();
  loops.erase(std::remove(loops.begin(), loops.end(), loop), loops.end());
}

// Pump every registered loop. Iterating to a (bounded) fixed point lets a chain of same-frame cross-loop
// posts settle within one browser frame instead of one loop per frame.
inline void pump()
{
  for (int iteration = 0; iteration < 64; ++iteration)
  {
    auto snapshot = cooperative_loops(); // copy: a loop may (un)register while being pumped
    for (auto *loop : snapshot)
      loop->poll();
    bool any_pending = false;
    for (auto *loop : cooperative_loops())
    {
      if (loop->has_pending())
      {
        any_pending = true;
        break;
      }
    }
    if (!any_pending)
      break;
  }
}

inline void set_frame_hook(std::function<void()> hook)
{
  cooperative_frame_hook() = std::move(hook);
}

inline void cooperative_driver()
{
  pump();
  if (auto &hook = cooperative_frame_hook())
    hook();
}

// Install the single browser main loop that drives all registered loops (and the optional frame hook,
// used by the renderer to draw after the loops settle). Idempotent.
inline void install_main_loop()
{
  static bool installed = false;
  if (installed)
    return;
  installed = true;
  emscripten_set_main_loop(&cooperative_driver, 0, 0);
}
} // namespace wasm

// Same public surface as the libuv thread_with_event_loop_t, but it spawns no thread: the loop is
// registered with the cooperative driver above and pumped on the single browser main loop. So
// processor_t / storage_handler_t / tree_handler_t construct it exactly as on native.
class thread_with_event_loop_t
{
public:
  thread_with_event_loop_t(const thread_with_event_loop_t &) = delete;
  thread_with_event_loop_t(thread_with_event_loop_t &&) = delete;
  thread_with_event_loop_t &operator=(const thread_with_event_loop_t &) = delete;
  thread_with_event_loop_t &operator=(thread_with_event_loop_t &&) = delete;

  thread_with_event_loop_t()
    : _event_loop()
  {
    wasm::register_loop(&_event_loop);
  }

  ~thread_with_event_loop_t()
  {
    stop_and_join();
  }

  // Idempotent, mirrors the libuv version's name so shared code can call it unconditionally.
  void stop_and_join()
  {
    if (!_deregistered)
    {
      wasm::unregister_loop(&_event_loop);
      _deregistered = true;
    }
  }

  [[nodiscard]] event_loop_t &event_loop()
  {
    return _event_loop;
  }

  [[nodiscard]] const event_loop_t &event_loop() const
  {
    return _event_loop;
  }

  [[nodiscard]] std::thread::id thread_id() const
  {
    return std::this_thread::get_id();
  }

private:
  event_loop_t _event_loop;
  bool _deregistered = false;
};

} // namespace vio
