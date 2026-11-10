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
Core Foundation never fires a timer or source again while its own callout is running, and a
nested turn can itself run inside one, because AppKit spins the run loop during ordinary calls.
The deadline is therefore a fresh one-shot timer each time it changes, never one re-armed in place:
a long-interval timer moved with `CFRunLoopTimerSetNextFireDate` from the before-waiting observer
never fired during tracking on CI, while a new timer does. The observer also fires it at once when
the kqueue has events while the descriptor source is the callout on the stack.

## G18. GL and Vulkan tests run without leak detection

Mesa loads and unloads driver modules while it probes for a device. LeakSanitizer then reports
driver allocations whose frames it can no longer name, and the report changes from run to run. The
Linux script runs every other test with leak detection on, and the GL and Vulkan cases in a second
pass with it off.

## G19. Window events are subscriptions, and subscriptions broadcast

`window_t::subscribe<Ts...>()` yields only the listed event types: `optional<T>` for one,
`optional<variant<Ts...>>` for several, everything for none. A typed await on one shared queue
would have to either discard what it skips, which steals it from other readers, or leave it there
to fill the queue. So each subscription has its own queue, registered before the first await, and
the window copies every event into each subscription that names its type. Nothing is consumed
from anyone else. Subscriptions are the only way to read input: the shared queue behind the old
`input()` was removed rather than kept beside them, because it duplicated the queueing and
delivery code and stored every event for a reader that might never come. An event of a type no
subscription names is therefore not stored at all. Order holds within a
subscription and not across two, which is why one subscription can name several types. The end of
the window is the end of the stream, not an error: an await yields `nullopt`, so
`while (auto e = co_await sub)` stops exactly then. Each subscription bounds its queue at
`input_queue_limit`, merges pointer moves and counts its own drops.

Resizes and close requests went the same way, as `resize_event_t` and `close_request_t` in
`window_event_t`. `resized()` and `close_requested()` had the defect `input()` had: one waiter took
each resize or request, so a renderer and a layout coroutine awaiting the same window each missed
what the other got. Neither needs a backlog -- only the latest size and the fact of a request
matter -- so a resize or close request that arrives straight after another of its kind replaces it,
the rule pointer moves already had. Being in the same variant also orders them against input, which
is what a dialog waiting for Escape or the close button wants. A subscription made after the
window's first size does not see it; `size()` answers that without a stream.

`frame()` stays an await, because awaiting a frame is what asks for one (`frame_wanted`): a
subscription would want frames for as long as it lived, which makes on-demand rendering
continuous, and a queued frame is a stale one. It already hands the same frame to every waiter of a
turn, so it never had the splitting defect. It now yields `std::optional<frame_t>`: its only error
was `canceled` on close, which is what `nullopt` means everywhere else, so every await in the
library ends the same way.

## G20. The UI beat is the loop's deferred queue

Everything the toolkit resumes -- a behaviour woken by a press, the frame loop woken by a change --
waits on the runtime's ready list and is resumed from one posted node on the loop's deferred queue,
so nothing runs on the stack of whatever recorded the event. The deferred queue rather than a
before-block hook, because a hook that runs before the display's pump can miss work the pump makes
ready and the loop then blocks with it pending; deferring a node instead makes the next wait return
at once. Frames are destroyed there too, never inside their own `final_suspend` or inside
`cancel()`. The one resumption that destroys the runtime -- the end of `ui::run`, once every scope
has drained -- goes through a second node of its own, so the beat that triggered it has returned
before the runtime goes.

## G21. Slots are keyed by address and type

A component's identity is its address, but a component and its first member share one, so the slot
map is keyed by the address and the view thunk together. No component can contain a component of
its own type at offset zero, so the pair is unique. Unmounting and mounting the same member again
makes a fresh slot: its behaviours start over, its state stays.

## G22. Cancellation is passed, not attached

`await_transform` cannot give an operation a `cancellation_t`: vio's one-shot operations take
the token as an argument when they are created, before the wrapper sees them, and readers have a
`cancel()` method instead. So a behaviour passes `scope.token()`, binds a reader with
`scope.bind()`, and the wrapper's suspension-point check is the backstop that makes
`while (true) co_await sleep(...)` end without either. The toolkit's own subscriptions are the
exception: the wrapper registers a callback that wakes them with `nullopt`.

Some operations resume their coroutine from inside `cancel()` (sleep does; the QUIC operations
latch and resume in their own beat), so a cancelled behaviour can run on the canceller's stack. It
only ever runs to its next `co_await`, where it is refused and buried, so nothing is freed under
whoever called `cancel()`. A frame parked inside an operation that took no token is never destroyed
-- the operation holds its handle -- and delays its component's release until the operation
completes.

## G23. The first renderer clears scissor rectangles

Every box is a `glScissor` and a `glClear`: no shaders, no buffers, nothing linked, only the
`proc<>` lookups. It draws coloured rectangles and nothing else, which is all phase 6 has. Layout
produces a flat list of `draw_item_t`, which is also what `run_config_t::on_layout` hands tests,
so a real renderer replaces this one behind the same list. Without a GL context (the null backend)
nothing is drawn and everything else runs.

Known gaps: redraws are driven by invalidation and resizes, so a damage-only expose with no resize
(possible on X11) is not repainted until something changes; and a behaviour that throws terminates,
as `task_t` does, rather than rethrowing out of `ui::run`.

## G24. The renderer reads a display list, not the hit-test list

`draw_item_t` is one entry per box because hit testing needs exactly that. A renderer needs
something else: a label is one box and dozens of glyphs, a plot is one box and thousands of
segments. Folding those into `draw_item_t` would make every pointer move walk them. So layout emits
two lists, and the component layer is unchanged by either.

## G25. Shaders are Slang, compiled offline and committed

One source gives SPIR-V, MSL and DXIL, and GLSL or WGSL if a GL or WebGPU backend is ever wanted.
Compiled at build time, never at run time: the Slang runtime is large and a UI has two or three
shaders. The outputs are committed so that building vio does not need `slangc` on `PATH`, a
requirement BoringSSL already makes of Go and NASM and which is not worth repeating for three
shaders.

## G26. Shapes are analytic distance functions, not tessellation

Rounded rects, borders, shadows, circles and arcs are one instanced quad each, with the exact
distance to the shape computed in the fragment shader and turned into coverage with `fwidth`.
Tessellation shaders were the alternative and lose on every count: D3D12, Vulkan and Metal each
model tessellation differently (Metal through compute), the output is triangles that still need
MSAA to look right, and it is a whole pipeline stage for primitives a few hundred pixels across.
These distances are exact, not sampled from a texture, so they have none of the softness of
distance-field text.

## G27. Text is FreeType and HarfBuzz into a coverage atlas

Signed distance field text was considered and rejected: at UI sizes (11-16 px) it is visibly
softer than a glyph rasterized at its size, a single-channel field rounds corners, and it has no
hinting. Its strength, one atlas entry for every size, matters for zoomable or transformed text,
which a UI rarely has. FreeType gives hinting and an outline rasterizer that also renders icons;
HarfBuzz gives shaping, without which only Latin text is right. FreeType is built with
`FT_DISABLE_HARFBUZZ=ON` so the two do not depend on each other. Both are dependencies of
`vio_gui_ui` only, through cmake-dep with the usual `VIO_USE_SYSTEM_*` toggles; neither the vio
core nor the window layer sees them. Blending is in linear space, because without it light text on
dark is too thin and dark text on light too heavy.

## G28. Plot lines are joined segments, and large series are decimated

A polyline drawn as independent capsules looks right only when opaque: translucent lines blend twice
where neighbours overlap and bead at every point. So each segment reads its neighbours from the
point buffer and the vertex shader builds a miter join, bevelled past a limit, with no overlap.
Series are uploaded relative to an origin subtracted in `double`, because `float32` cannot hold a
timestamp axis and zooming into one jitters. Past one point per pixel column, M4 decimation keeps
the first, last, minimum and maximum of each column, which is pixel-identical for a line plot and
turns a million points into a few thousand segments.

## G29. Updates are cached per component on the CPU, rebuilt whole on the GPU

The whole window is rendered every frame, so the saving is not in drawing less. It is in not
producing what has not changed, because `view()`, layout and text shaping are the expensive part
of a frame. Each slot keeps its own commands, in its own coordinates, and a measured size with the
constraints behind it. A change marks `subtree_dirty` upward, stopping at the first ancestor
already marked, and only marked subtrees are revisited. It is a separate flag from `view_dirty`:
marking a parent view-dirty would re-run user code for every change below it.

Commands are grouped in chunks rather than kept one list per slot. Most components produce a few
primitives each, and assembling a frame from thousands of tiny copies would pay per-copy overhead
on all of them. So a subtree below a threshold flattens into its ancestor's chunk, with hysteresis
so one near the limit does not switch every frame. Flattened copies at *every* level were rejected:
memory grows with depth, a leaf change re-flattens every ancestor, and the root's copy is the whole
window anyway. With chunks every command lives in exactly one, and a rebuild is bounded by the
threshold.

The instance buffer is concatenated afresh every frame rather than patched in place. Patching
would need an allocator over the buffer and a plan for chunks that change length, to save a copy
of tens of microseconds. Offsets are applied in the shader from a buffer of chunk origins, so that
copy is a plain `memcpy` and moving costs one origin. Boundaries, which hold their own GPU buffers,
are for the subtrees large enough that even the copy matters. Data that is large in itself -- the
atlas, plot series, heatmaps -- lives in its own GPU resources and is never part of any copy.

## G30. Vulkan is the renderer's first backend

It is the one backend that can be tested everywhere the window layer is: lavapipe runs it in Linux
CI under Xvfb and weston, as phase 3 already does for surfaces, and the same code runs on Windows.
D3D12 would be testable only on Windows and Metal only on macOS. It also sidesteps WGL, whose
context creation fails on the Windows machine the toolkit was first run on. D3D12 and Metal follow
once the display list, shaders and text are settled on Vulkan.
