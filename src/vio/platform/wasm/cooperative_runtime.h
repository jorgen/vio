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
#pragma once

// Public entry point for the cooperative single-thread multi-loop runtime used by the WebAssembly
// build. The API lives in namespace vio::wasm:
//
//   register_loop(event_loop_t*) / unregister_loop(event_loop_t*)  (usually via thread_with_event_loop_t)
//   pump()                 - pump every registered loop once (to a bounded fixed point)
//   set_frame_hook(fn)     - run fn each frame after the loops settle (the renderer draws here)
//   install_main_loop()    - install the single emscripten_set_main_loop driver (idempotent)
//
// The definitions are in platform/wasm/event_loop_impl.h (where event_loop_t is complete); this header
// just pulls them in via <vio/event_loop.h>, which selects the wasm platform under __EMSCRIPTEN__.

#include <vio/event_loop.h>
