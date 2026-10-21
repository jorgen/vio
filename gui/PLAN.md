# vio gui

A window library on the vio event loop. Windows, input and frames are awaited from coroutines on
the same loop that runs sockets, timers and files. `DECISIONS.md` in this directory records each
choice and its reason.

## Goals

1. One loop. Window-system events wake the same `event_loop_t` as I/O; there is no second thread
   and no second loop to hand work across.
2. Everything is awaited: a frame to draw, input, a resize, a close request.
3. One interface for what every window system does: create, title, size, position, visibility,
   fullscreen, minimise and maximise, cursor, clipboard, content scale.
4. Rendering contexts for OpenGL, Vulkan, Metal and Direct3D 12, set up from a window, and the
   handles OpenCL and CUDA need to share with them.
5. macOS (Cocoa), Windows (Win32), Linux on X11 and on Wayland.
6. No hard link to a graphics API. GL, EGL and Vulkan are loaded at run time, so a program that
   never asks for one does not need it installed.

## Example

```cpp
vio::event_loop_t loop;
auto display = vio::gui::display_t::open(loop);
auto window = vio::gui::window_t::create(*display, {.title = "hello", .size = {800, 600}});

auto draw = [](vio::gui::window_t &window) -> vio::task_t<void> {
  auto gl = vio::gui::gl_context_t::create(window, {});
  while (auto frame = co_await window.frame())
  {
    gl->make_current();
    render(frame->size);
    gl->swap_buffers();
  }
}(*window);

auto read_input = [](vio::gui::window_t &window) -> vio::task_t<void> {
  while (auto event = co_await window.input())
    handle(*event);
}(*window);

auto wait_close = [](vio::event_loop_t &loop, vio::gui::window_t &window) -> vio::task_t<void> {
  co_await window.close_requested();
  window.close();
  loop.stop();
}(loop, *window);

loop.run();
```

`frame()` works like `requestAnimationFrame`: each await asks for one frame, and it resolves at
the next point the display can show one. Awaiting it in a loop renders continuously; awaiting it
only after a change renders on demand. A window that was exposed or resized resolves the next
await at once.

`input()` yields events in order. `resized()` yields the latest size; sizes that arrive while
nobody waits are merged into one. `close_requested()` resolves when the user asks to close; the
window stays open until the program closes it.

Each await yields `std::expected<T, error_t>`. Once the window is closed, every waiter and every
later await gets `errc::canceled`.

## The loop

The window system joins the loop in one of two ways.

**Linux.** The X11 or Wayland connection is a socket. It is added to the backend like any other
socket. A before-block hook flushes requests and dispatches what was read. Nothing else changes.

**macOS and Windows.** The window system wants its own wait: `nextEventMatchingMask` on macOS,
`MsgWaitForMultipleObjectsEx` on Windows. The loop gets a *host wait*: when one is set, the loop
blocks in the host wait instead of in the backend, then polls the backend without blocking.

- macOS: the kqueue descriptor is a `CFFileDescriptor` on the main run loop. When it fires, it
  posts an empty application event, which ends the wait.
- Windows: an I/O completion port cannot be waited on together with the message queue. A
  forwarder thread waits on the port, puts each packet it takes straight back, and posts a message
  to a hidden window, which ends the wait. Electron drives libuv the same way.

### Modal loops

Resizing a window by its border runs a loop inside the window system on both macOS and Windows,
and the program's own loop does not run until it ends. Animations stop and a resized window shows
stale content.

vio runs turns from inside those loops. On macOS the descriptor source and a deadline timer are
registered in the common run-loop modes, so they also fire during live resize. On Windows the
forwarder's message reaches the hidden window inside the modal loop too, and a `SetTimer` started
on `WM_ENTERSIZEMOVE` covers deadlines. Each runs `loop_core_t::run_nested()`, one turn that never
blocks and skips any stage already on the stack.

### Resuming coroutines

The window system's callbacks only record events. A before-block hook resumes the waiters, after
the dispatch hook in the same turn. A coroutine may therefore close its window, or drop the last
handle, without pulling storage out from under a callback that is still running. The QUIC
coroutine layer works the same way.

## Frame pacing

| platform | source of frames |
|----------|------------------|
| Wayland  | `wl_surface.frame` callbacks |
| macOS    | a loop timer at the screen's refresh rate (`NSScreen.maximumFramesPerSecond`) |
| X11      | a loop timer at the monitor's refresh rate (XRandR) |
| Windows  | a loop timer at the monitor's refresh rate (DWM) |

A frame is never delivered to a window that is minimised or hidden.

## Rendering contexts

| API | Linux | macOS | Windows |
|-----|-------|-------|---------|
| OpenGL | EGL | NSOpenGLContext | WGL |
| Vulkan | `VK_KHR_xlib_surface`, `VK_KHR_wayland_surface` | `VK_EXT_metal_surface` | `VK_KHR_win32_surface` |
| Metal | | `CAMetalLayer` | |
| Direct3D 12 | | | DXGI flip-model swap chain |

For Vulkan, the library reports the instance extensions a window needs and creates the surface
from the program's instance. It never creates the instance or device; those choices belong to the
program. Direct3D 12 is the same: the program gives the command queue and gets a swap chain.

## OpenCL and CUDA

Sharing is set up on the window-system side only:

- OpenCL: the `cl_context_properties` for `cl_khr_gl_sharing` (`CL_GL_CONTEXT_KHR` with
  `CL_EGL_DISPLAY_KHR`, `CL_WGL_HDC_KHR` or `CL_CGL_SHAREGROUP_KHR`) from a GL context.
- CUDA: the device that drives a window is found by matching identifiers: the LUID of a DXGI
  adapter on Windows, the UUID from `VkPhysicalDeviceIDProperties` for Vulkan.

Neither OpenCL nor CUDA is linked or loaded by the library.

## Phases

| phase | work | verified by |
|-------|------|-------------|
| 1 | host wait and nested turns in the vio core | core unit tests |
| 2 | display, window and awaited channels; X11 and Wayland | tests under Xvfb and headless weston |
| 3 | EGL, GL and Vulkan surfaces on Linux; interop properties | tests under Xvfb and weston, llvmpipe and lavapipe |
| 4 | Win32 backend, WGL and Direct3D 12 | Windows CI |
| 5 | Cocoa backend, NSOpenGL and Metal | macOS CI |
