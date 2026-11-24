/*
Copyright (c) 2026 Jørgen Lind

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

#pragma once

// The cooperative layer on the browser backend (D69). Every loop runs its own turns, so nothing
// here is needed to make a loop make progress. It is for a host that renders: pump() settles
// every registered loop, to a bounded fixed point, before a frame is drawn, and wake() asks an
// on-demand renderer for a frame when work finishes outside one.
//
//   register_loop / unregister_loop   usually through thread_with_event_loop_t
//   pump()                            one turn of every registered loop, repeated while any has work
//   set_frame_hook(fn)                fn runs each frame after the loops settle
//   install_main_loop()               one emscripten_set_main_loop that pumps and calls the frame hook
//   set_wake_hook(fn) / wake()        fn runs when asynchronous work completes outside a frame

#ifndef __EMSCRIPTEN__
#error "vio/platform/wasm/cooperative.h is for the WebAssembly build"
#endif

#include <algorithm>
#include <functional>
#include <vector>

#include <emscripten.h>

#include "vio/platform/native/event_loop_impl.h"

namespace vio
{
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

inline std::function<void()> &wake_hook()
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

inline void pump()
{
  for (int iteration = 0; iteration < 64; ++iteration)
  {
    auto snapshot = cooperative_loops(); // a loop may register or unregister while it is pumped
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

inline void set_wake_hook(std::function<void()> hook)
{
  wake_hook() = std::move(hook);
}

inline void wake()
{
  if (auto &hook = wake_hook())
    hook();
}

inline void cooperative_driver()
{
  pump();
  if (auto &hook = cooperative_frame_hook())
    hook();
}

inline void install_main_loop()
{
  static bool installed = false;
  if (installed)
    return;
  installed = true;
  emscripten_set_main_loop(&cooperative_driver, 0, 0);
}
} // namespace wasm

inline thread_with_event_loop_t::thread_with_event_loop_t()
{
  wasm::register_loop(&_event_loop);
  _event_loop.run();
}

inline void thread_with_event_loop_t::stop_and_join()
{
  if (_stopped)
    return;
  _stopped = true;
  wasm::unregister_loop(&_event_loop);
  auto &core = detail::core(_event_loop);
  _event_loop.stop();
  for (int turn = 0; turn < 1024 && core.running(); ++turn)
    core.run_host_turn();
}
} // namespace vio
