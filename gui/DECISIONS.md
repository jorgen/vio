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

Known gap: a behaviour that throws terminates, as `task_t` does, rather than rethrowing out of
`ui::run`. (The other gap recorded here, an expose with no change going unpainted, is closed by
G36. This renderer is now the GL fallback of G32 and reads the display list of G24.)

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
window anyway. With chunks every command lives in exactly one.

What the threshold does *not* bound, as built: a holder's chunk holds its own commands and those
of every descendant too small to hold one, so a parent of a thousand 100-primitive children holds
one chunk of 100,000 and flattens all of it when any child changes. And a holder that is marked
only because a nested holder below it changed flattens again although none of its own content did.
Both are bounded by what the window shows, both are cheap next to running views, and neither is
fixed: the first wants a holder that grows past a multiple of the threshold to promote its largest
inlined children; the second wants a third flag, set only by changes that land in the holder's own
chunk.

The instance buffer is concatenated afresh every frame rather than patched in place. Patching
would need an allocator over the buffer and a plan for chunks that change length, to save a copy
of tens of microseconds. Offsets are applied in the shader from each run's origin (G34), so that
copy is a plain `memcpy` and moving costs one origin. Boundaries, which hold their own GPU buffers,
are for the subtrees large enough that even the copy matters. Data that is large in itself -- the
atlas, plot series, heatmaps -- lives in its own GPU resources and is never part of any copy.

## G30. Vulkan is the renderer's first backend

It is the one backend that can be tested everywhere the window layer is: lavapipe runs it in Linux
CI under Xvfb and weston, as phase 3 already does for surfaces, and the same code runs on Windows.
D3D12 would be testable only on Windows and Metal only on macOS. It also sidesteps WGL, whose
context creation fails on the Windows machine the toolkit was first run on. D3D12 and Metal follow
once the display list, shaders and text are settled on Vulkan.

## G31. The renderer owns its Vulkan device unless the program lends one

The window layer never creates a device; a toolkit that draws has to. So by default the renderer
creates its own instance and device, picking a discrete GPU over an integrated one over anything
else (lavapipe last), and a queue family that can present to the window. A program that already
renders passes `run_config_t::vulkan_device` -- instance, physical device, device, queue, family
and its `vkGetInstanceProcAddr` -- and the renderer makes only its surface, swapchain, pipeline and
buffers on it, destroying those and nothing else. The program must have enabled the instance's
surface extensions (`vulkan::required_instance_extensions`) and the device's `VK_KHR_swapchain`,
and must not use the queue from another thread while the loop draws: Vulkan queues are externally
synchronised and the renderer submits from the loop thread. Handles cross the public header as
`void *`, so `ui.h` needs no `vulkan.h`.

## G32. The GL stopgap stays as the fallback

`render_api_t::automatic` tries Vulkan, then GL. GL is still G23's scissor-clear renderer, now
reading the display list: square corners, no borders, no shadows. It stays until Vulkan has run on
every platform CI covers, because until then it is the only thing that draws on a machine whose
Vulkan loader or driver is missing. `run_config_t::on_renderer` says which was chosen and why
Vulkan was not, since a silent fallback looks like a styling bug. Removing it is phase 12's call.

## G33. The committed SPIR-V is a stopgap from a GLSL transcription

`ui.slang` is the source of truth (G25), but the first `ui_spirv.h` was not compiled from it.
Downloading slangc was refused in the session that wrote the renderer, and nothing installed on the
machine compiled Slang. RenderDoc's `glslangValidator` 16.2.0 was installed, so the two entry
points were transcribed to GLSL by hand -- same attribute locations, same push-constant block, same
arithmetic -- and compiled with that; the transcription is not in the tree. The header says so in
its first lines. Regenerate it with `cmake --build <dir> --target vio_gui_shaders` once slangc is
on `PATH`, then run `test_ui_render.cpp`: the offscreen test reads back pixels and is what proves
the Slang output matches. The renderer reads each module's entry point name out of its
`OpEntryPoint`, so slangc keeping `vertexMain` where glslang writes `main` needs no change. The
target builds for `spirv_1_0` because the renderer asks for Vulkan 1.0.

## G34. A run's origin is a push constant, not an index into a buffer

G29 planned a buffer of chunk origins indexed per instance. One `vkCmdDraw` per run with the origin
pushed does the same job without a descriptor set, a second buffer or a field in every primitive,
and the number of runs is the number of chunks, roughly primitives / threshold -- dozens, not
thousands. The cost is a draw call per run. When the glyph atlas brings descriptor sets in phase 10,
or a profile shows draw calls, the buffer is the change to make; the display list already carries
everything it needs.

## G35. Layout is in logical units, on every platform

`frame.framebuffer / frame.scale` is the window's size on Wayland and macOS and its size divided by
the UI scale on Windows and X11 (G9), so one expression gives the same unit everywhere. Before
this, layout used `frame.size`, which is pixels on Windows and X11 -- a 60-unit box
was 60 pixels at any DPI. Pointer positions arrive in the window system's units and are scaled by
logical / size before hit testing. Sizes stay integers; the renderer scales by framebuffer /
logical, per axis, in floating point. Only the null backend (scale 1) is under test, so the
conversion itself has been seen working only in the counter example at 144 DPI.

## G36. An expose is an event in the window layer

The frame loop sleeps in `changed()` and a window's `damaged` flag reached nobody until something
else asked for a frame -- the G23 gap. `expose_event_t` joins `window_event_t`, emitted when the
window system reports damage and when a hidden window is shown again, so a subscriber learns that
its contents were lost. It is an event rather than a flag on `frame()` because frames are only
delivered when asked for (G5): a program waiting for a reason to draw needs to be told. The UI
subscribes to it beside `resize_event_t`; the frame that follows runs no view and reuses every
chunk, which `test_ui_render.cpp` checks.

## G37. A shadow is the Gaussian of the distance, not the exact convolution

The shadow's coverage is `0.5 - 0.5 erf(d / (sqrt(2) sigma))` of the same rounded-box distance the
box itself uses. It is exact along straight edges and an approximation at corners, where the true
convolution of a rounded rectangle is slightly darker. Evan Wallace's closed form integrates the
corners properly but is several times the code; at UI shadow sizes the difference is not visible.
The quad grows by three sigmas so the tail is not clipped.

## G38. Colours are sRGB as authored, blended in linear space

`color_t` values are what a designer types -- sRGB, straight alpha. The vertex shader converts to
linear and premultiplies; blending is `ONE, ONE_MINUS_SRC_ALPHA`; the swapchain is an `_SRGB` format
so the hardware encodes on write. Where a surface offers no sRGB format the shader encodes itself
(`encode_srgb` in the push constants). The clear colour is converted on the CPU to match. This is
what G27 asks of text, set up before text arrives.
