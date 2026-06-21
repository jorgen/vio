#pragma once

#include "vio/about_to_block.h"
#include "vio/task.h"

#include <cassert>
#include <functional>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include <emscripten.h>

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

} // namespace vio
