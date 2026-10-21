# Decisions

Each entry is a choice made while building vio gui, and why. `PLAN.md` describes the design.

## G1. The library lives in the vio repository

It needs hooks in the loop core (G2) that change with it, and one CI run then checks both. It is
its own target, `vio_gui`, in its own directory, so it can move to its own repository once the
core hooks settle.

## G2. A host wait, not a host loop

The loop keeps control of the turn. On macOS and Windows a *host wait* replaces only the blocking
step. The other way round, where the window system's loop runs and calls vio, would make the turn
order depend on the platform, and every vio guarantee about it would need restating per platform.

## G3. Nested turns run inside modal loops

The open question in the core `DECISIONS.md` was whether coroutines should run while Win32 or Cocoa
holds the thread in a resize or move loop. They do. Without it, a window being resized shows
stale content, and I/O stalls for as long as the user holds the mouse button. `run_nested()` skips
each stage that is already running further up the stack, so no queue is walked twice at once.

## G4. Callbacks record, a hook resumes

Window-system callbacks only queue events. A before-block hook resumes the waiters. A coroutine
that closes its window then cannot free the window while Xlib, libwayland, AppKit or a window
procedure is still running on it.

## G5. Frames are requested, not pushed

Each await of `frame()` asks for one frame. A program that is idle draws nothing and the loop
sleeps. This matches `wl_surface.frame` and `requestAnimationFrame`.

## G6. Graphics APIs are loaded at run time

EGL, GL, GLX and Vulkan are loaded with `dlopen` (or `LoadLibrary`) on first use. A program that
draws with Vulkan does not need libGL, and one that only opens windows needs neither.

## G7. Window systems are linked on Linux

libX11 and libwayland-client are linked. Both are present on any desktop that can show a window,
and loading them at run time would add a table of some two hundred function pointers for no
gain. The backend is chosen at run time: Wayland when `WAYLAND_DISPLAY` is set, X11 otherwise,
and `VIO_GUI_BACKEND=x11|wayland` overrides.

## G8. EGL for OpenGL on Linux

EGL works on X11 and Wayland alike, so one code path covers both. GLX would serve only X11.

## G9. Sizes are in the window system's own units

`size` is pixels on X11 and Windows, and logical units on Wayland and macOS. `framebuffer` is
always pixels, and `scale` is the factor between them, or the user's UI scale where the two are the
same (X11's `Xft.dpi`). Render at `frame.framebuffer`; lay out at `frame.size`. GLFW draws the
same line, and anything else would mean inventing a unit one of the four systems does not have.

## G10. A context is released when its window closes

A GL context and its surface hold the native window. When the window closes, every attachment is
told first and drops its native objects; later calls answer `errc::canceled`. Otherwise closing a
window before its context would leave EGL holding a destroyed `wl_surface` or X window.

## G11. EGL is loaded once and never unloaded

Mesa's drivers keep thread-locals and register exit handlers. Unloading them while those are live
crashes at exit on some versions. Keeping the library also lets LeakSanitizer attribute what the
driver allocates, and with it loaded the suite reports no leaks.

## G12. Wayland swaps with interval zero

The frame callback already paces a Wayland window. An EGL swap interval of one would make
`eglSwapBuffers` wait for a second callback of its own and block the loop thread meanwhile. On X11
the interval follows `gl_config_t::vsync`, since nothing else there knows where vertical blank is.

## G13. Wayland frames need a commit

`frame()` on Wayland resolves from a `wl_surface.frame` callback asked for when the previous frame
was handed out. The compositor answers only once that frame is committed, so a program that awaits
frames must present each one (`swap_buffers`, a Vulkan present, or its own commit). A window the
compositor hides gets no callbacks and so no frames, which is the point.

## G14. A loop timer paces frames on X11, Windows and macOS

Only Wayland tells a client when to draw. Elsewhere a timer on the loop fires at the display's
refresh rate, aligned to the clock, so windows that share a rate tick together. A display link
thread (`CVDisplayLink`, `DwmFlush`, the X Present extension) would be closer to vertical blank but
would add a thread per display and a post per frame. The swap interval still holds the picture to
vertical blank where the driver supports it.

## G15. One host wait per thread

Windows and macOS deliver window messages per thread, not per window, so one host wait serves
every display on a loop. A second display shares it, and a display on another loop on the same
thread is refused with `errc::busy`.

## G16. Windows: a forwarder thread puts completions back

An I/O completion port cannot be waited on together with the message queue. The forwarder thread
takes one batch of completions when the loop is about to wait, posts each straight back to the
port, and posts a message to a hidden window, which ends `MsgWaitForMultipleObjectsEx`. It takes
only one batch per wait, so it never spins while the loop is busy. Electron drives libuv the same
way. The cost is one thread and the reordering of completions within a batch, which nothing in
vio depends on.

## G17. Inside a modal loop, deadlines keep the window system's timer resolution

During a Win32 size or move loop, vio's own deadlines arrive through `WM_TIMER`, which the system
delivers at roughly 16 ms; I/O still wakes a turn at once through the forwarder. A 5 ms sleep
therefore runs at about 60 Hz while the user drags a border, and at full speed again afterwards.
On macOS the deadline timer is a `CFRunLoopTimer` in the common modes, re-armed before every wait,
since vio's timers are not kqueue events and would not otherwise end a tracking loop's sleep.

## G18. GL and Vulkan tests run without leak detection

Mesa loads and unloads driver modules while it probes for a device. LeakSanitizer then reports
driver allocations whose frames it can no longer name, and the report changes from run to run. The
Linux script runs every other test with leak detection on, and the GL and Vulkan cases in a second
pass with it off.
