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

**Resolved.** `-DVIO_GUI_FETCH_SLANG=ON` fetches slangc 2026.21's release archive for the host
through cmake-dep (one package per host system and processor, since the archives are prebuilt;
off by default, so neither the lockfile nor CI fetches it), and `ui_spirv.h` is now its output.
It found one difference the transcription hid: Slang's `SV_VertexID` is zero-based as in
Direct3D, so it subtracts `BaseVertex`, which needs `DrawParameters` and silently raised the
vertex module to SPIR-V 1.3 -- invalid on a Vulkan 1.0 device. The shader uses
`SV_VulkanVertexID` instead; every draw starts at vertex 0, so the value is the same. slangc
still warns that 1.0 is "too old"; it is advisory and both modules are 1.0. The tests and the
counter example draw the same through it as through the stopgap.

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

## G39. Glyphs and icons are coverage prims into one R8 atlas, rounded at a shared anchor

A coverage prim is a rectangle of the atlas copied texel for texel: no sampler, no filtering, one
texel per pixel. That holds only if the rectangle lands on whole pixels, and layout cannot place it
there itself -- a run's origin and a non-holder's offset are logical units, which at 1.5x are half
pixels. So a glyph carries a logical anchor (its text node's position) and an integer pixel offset
from it, and the vertex shader rounds the anchor. Every glyph of a text shares the anchor and rounds
the same way, so HarfBuzz's spacing is kept exactly; rounding each glyph would shift them by
different amounts. The subpixel offset (one of four) is chosen from the pen position relative to the
anchor, which is what the rounding preserves.

FreeType renders with light hinting -- vertical only -- because HarfBuzz's advances are unhinted and
full hinting would change widths under them. Both are fetched by cmake-dep: FreeType 2.15.0 with
HarfBuzz, zlib, bzip2, PNG and Brotli off; HarfBuzz 15.1.0 compiled from its `harfbuzz.cc`
amalgamation with its own OpenType font functions, so neither sees the other. Both are private to
`vio_gui_ui`.

The atlas is shelf-packed, starts at 512 square and doubles to 4096; full at that size it is emptied
and the frame lays everything out again once, since what was laid out before names rectangles that
are gone. A new scale empties it too, because every glyph's pixel size changes. One atlas per
runtime: FreeType faces are not thread-safe and a window's loop owns its runtime, so nothing is
locked. `font_t` itself -- the bytes and an `hb_face_t` -- is immutable and shared.

Uploads are the dirty rectangle since the previous display list, through a per-frame staging buffer,
before the render pass. The barrier after the copy waits on all commands, not only transfer, and
that is empirical: on an RX 5700 XT with a frame in flight, a copy whose rows were not 4-byte
aligned was not there when the same frame's fragments read it, so new glyphs (the clock's digits in
the counter example) did not appear. Waiting for idle after each frame, aligning the copy, or
widening the barrier's source stage each fixed it; the offscreen test, which waits between frames,
never showed it. The spec reading is that `TRANSFER -> FRAGMENT_SHADER` suffices; no validation layer
was available to say otherwise, so treat this as a driver workaround until one does. It costs
nothing measurable: it runs only on frames that upload.

## G40. A text node is one line, one font, one direction

`text_t` is shaped as a single HarfBuzz run whose direction, script and language HarfBuzz guesses
from the text. A line of Arabic, Hebrew or Devanagari is right; a line mixing directions is not,
because that needs the Unicode bidirectional algorithm to split it into runs first. Missing glyphs
draw as the font's .notdef: there is no fallback list. No wrapping, and a row aligns tops, not
baselines. Each of those is real work with a library or an algorithm behind it (SheenBidi or
fribidi, fontconfig or a fallback table, line breaking per UAX 14), and none is needed to put a
label on a UI. The default font is found by path -- Segoe UI, the macOS system font, DejaVu, Noto or
Liberation Sans -- rather than through fontconfig, which would be a third dependency loaded at run
time for one lookup; `run_config_t::font` overrides it. Colour glyphs (emoji) are not drawn: the
atlas is one channel.

## G41. Layout is one pass with padding and alignment; plots start as segments and areas

Layout stays content-sized and single-pass: a container places each child at its start position,
learns its size from doing so, and only then moves it -- across for alignment, down for a baseline
-- by shifting the entries the child produced. No constraints travel down, so nothing yet grows to
fill a row (flex); that is a second pass and waits for a layout that needs it. Positions became
`float`, because two things need fractions: a plot's bars move by fractions of a unit as they
scroll, and baselines do. A text's baseline is a whole number of pixels below its anchor, which the
shader rounds; moving the anchor by exactly the difference of two baselines in logical units --
fractional at 1.5x -- therefore lands both on the same pixel row, where rounding the move to whole
units missed by one. Hit testing rounds positions; drawing keeps them.

A box with children holds them overlapping, each aligned inside its padding, rather than as a
column: one child is the common case (a label on a button), and a column inside is one more node.
`at_t` exists for what alignment cannot say -- a bar at a time-dependent x.

Plots begin inside the existing pipeline, ahead of phase 11's point buffer (G28). `polyline_t`
emits one segment prim per segment -- the distance to the segment, so ends and joins are round --
one area prim per segment of fill, and one circle per marker. Round joins overlap, so a translucent
line darkens at every point; G28's joined segments remove that, and until then the example's lines
are opaque. A line is rebuilt with its component, which at a few thousand prims is cheap.

Areas meet edge to edge, and that edge is not the rasterizer's to decide. The first version made
each area's quad exactly x0 to x1 and relied on shared edges rasterizing once; the offscreen test
of one shared edge at 2x passed, and the running example at 1.5x showed stripes where the fill was
blended twice. SPIR-V lets the driver contract and reorder vertex arithmetic per vertex, so two
vertices computed from the same float need not land on the same position. The quad is now a pixel
wider on each side, and the fragment shader keeps a pixel only if its centre, mapped back to the
run's logical x, lies in [x0, x1) -- bounds passed through from the attributes with no arithmetic,
compared against a value computed the same way for that pixel in either prim, so exactly one of
two neighbours keeps it. A test of three hundred thin areas at 1.5x on a fractional origin failed
on 174 pixels of one row before that, and passes after.

Centring a text centres its line -- ascent plus descent -- as CSS does, and a "+" or "-" sits on
the font's maths axis, below the middle of that line: in Segoe UI the example's button labels were
5.5 px low at 1.5x. `text_t::tight` measures a text by its ink instead, moving its glyphs by whole
pixels so they stay texel-exact; it is opt-in, because a line of text must keep its line's height
or neighbouring lines of different content would not match. A centred offset is also snapped to the
nearest pixel rather than floored to a whole unit, which at 1.5x is worth up to three quarters of a
pixel. The labels are now within half a pixel of centre.

## G42. Flex is measure-then-place where space is handed out; lists own by shared pointer

Flex needs a child's natural size before the child is placed, which a one-pass layout cannot give.
Rather than a second, separate measuring function per node type -- which would have to agree with
placing forever -- measuring is placing and taking it back: the entries are truncated and the
counters restored, and the result is cached for the frame by the node's address, so nesting does
not multiply it. Only a container that hands out space (a child grows or stretches, or it was given
a size itself) measures; everything else is still placed once. A mounted component is laid out for
the size it is given and keeps its natural size from its last unconstrained layout, so a clean
child is measured for free. The root is given the window, which is what lets a page fill it.

`list_t<T>` holds its items by `shared_ptr` and its mounts share that ownership with the slot: an
erased item's behaviours still hold `this` until they reach their next await, so the item is freed
when the slot is reaped, not at `erase()`. Props are carried type-erased on `mount_t`, compared each
frame and copied into the child only when they differ, which is what rebuilds it. A child scope is
cancelled through a callback on its parent's token, and its owner must join it; that await, and
awaiting a spawned job, are exempt from the refusal a cancelled scope gives every other await,
because both are bounded by the cancellation itself and refusing them would end the owner while
what it owns still runs. `job_t<T>` keeps its result outside its frame, since the scope destroys the
frame a beat after it ends.

## G43. A merge is one waiter watching several queues

`ui::merge(scope, a, b, c)` does not put a waiter into each subscription's queue: several waiters for
one coroutine could each be readied in the same turn and resume it twice, and whichever lost would
have taken an event out of its queue for nobody. Instead each queue gets a watcher pointer. An event
that no direct awaiter takes is queued as before and readies the watcher, at most once -- a waiter
already readied is skipped -- and the merge, when it runs, stops watching every queue and takes from
the first non-empty one, starting after the one it took from last so a busy source cannot starve a
quiet one. Events are never removed from a queue until the merge consumes them, so none is lost or
seen twice. The result is a variant indexed by argument position, so two subscriptions of one event
type stay distinguishable.

`ui::every` and `ui::lines` are behaviours in the scope feeding a source the subscription reads.
They mark themselves quiet: their own wake-ups do not rebuild the component, which a ticker at
16 ms would otherwise do every period whether or not anything consumed the tick. A stream's end is
an event (`line_t::closed`), not the source going away, which would leave a waiting merge waiting.
Tested against a real loopback TCP connection with a line split across writes and a CRLF.

## G44. Plot lines are mitred segments in the one pipeline; heatmaps live in the atlas

G28 planned a point buffer read by the vertex shader, a pan-and-zoom uniform, triangle strips for
fills and an R32F texture for heatmaps. What was built keeps everything in the instanced-prim
pipeline the rest of the toolkit uses, because each of those would have been a second pipeline,
buffer or descriptor for one feature, and the prim was enough:

- **Joins.** A segment carries, at each end, the plane its neighbour shares: through the joint,
  square to the sum of the two directions, which is the mitre line. The CPU writes the same floats
  into both segments; the shader tests the pixel against it in logical units with `precise`
  arithmetic (SPIR-V `NoContraction`), so the two compute the same answer and exactly one draws the
  pixel -- the lesson of the area seams in G41, applied before the stripes showed this time. Inside
  its planes a segment is a band square to its line, which is the mitre; a zero normal is a round
  end, used at the line's ends and past a mitre limit of 4, where a mitre would spike. A test
  renders a half-transparent zigzag and finds no pixel blended twice; with the joins turned round
  it finds some.
- **Decimation** is M4 on the CPU where the line is placed: per pixel column the first, lowest,
  highest and last point. A million points become about four hundred segments, and the extremes
  survive (a one-point spike is tested for). Lines whose x goes backwards are not decimated.
- **Heatmaps** are quantized to 256 levels into a region of the R8 glyph atlas, keyed by the data's
  address and re-quantized only when its `version` or range changes, so an updating spectrogram
  uploads only its own rectangle through the dirty-rect path G39 already had. The colormap is a
  polynomial fit of viridis in the shader. 256 levels is below what a colormap can show; the cost
  is that a heatmap's region is never freed until the atlas fills, and that a heatmap is at most
  4096 cells a side.

Not built: pan and zoom as a uniform. A plot that pans rebuilds its prims, which at a few thousand
per plot after decimation is cheap; a million-point series is decimated per rebuild, which costs
the walk over a million points.

## G45. What a 200,000-chip scene needed: mount lists, culling, and zoom as a run scale

The chip stress test (PLAN.md, "Stress test") was measured first and changed after, and each change
is what a profile of that build pointed at:

- **A clean view's mounts are kept, not searched for.** Finding the mounted children of a component
  walked its whole cached node tree every frame, so a scene whose 400 tiles had not changed still
  walked 200,000 chip nodes: 8 ms a frame of panning with no view run. Each slot now records its
  mounts when its view runs. Panning everything went from 18.6 to 4.0 ms.
- **Hit testing collects only what a press can be aimed at,** and skips subtrees with none, unless
  `on_layout` asks for every box; the chips have no pressables, so their 200,000 boxes cost nothing.
- **Chunks and hit-test items wholly outside the window are skipped** (with a margin for shadows). A
  chunk skipped while it changed is flattened again when it next comes into view, and so is every
  holder below it on the changed path, since the per-frame dirty marks are cleared either way.
- **Zoom is a scale on the run, applied by the GPU.** `mount_t::scale` draws a component that many
  times its layout size without laying it out again; positions, sizes, radii, borders and line
  widths scale in the shader, glyphs keep their pixel size and move with their anchor (they are
  texel-exact), and layout and hit testing see the scaled size. A scaled mount is always a holder,
  since the scale belongs to a run. The scene lays tiles out at zoom steps a factor of the square
  root of two apart and scales between them, so a zoom gesture rebuilds nothing until it crosses a
  step: zooming with everything in view went from 81 to 6.3 ms. This is the "pan and zoom as a
  uniform" G28 planned, at the level of a mount rather than a plot.
- **`run_config_t::on_stats`** reports each frame's cost by phase, which is how all of the above
  was found.

The stress test also found a shutdown race the examples had always had: the runtime read the event
loop through the window, and a behaviour woken by its own timer after the window closed -- before
the frame loop noticed -- asked for the loop through a window that no longer had one. The runtime
now keeps the loop from construction. `vio_gui_ui_counter`'s timed exit failed about two runs in
five before and none in twenty after; a unit test on the null backend did not reproduce it, so
there is none.

## G46. Widgets are controlled components; focus and popups are the runtime's

`vio/gui/ui/widgets.h` has the first widgets: `button_t`, `checkbox_t` and `combobox_t`. Each is an
ordinary component built only from what `ui.h` offers any program, which keeps them honest as a
worked example and kept the toolkit changes to the two things a combobox could not do without.

- **Controlled, not self-owned.** A widget's value comes down as props and a change comes up as an
  event (`toggle_event_t`, `select_event_t`) on a public `event_source_t` member, which the parent
  applies to its own state. PLAN.md's rule that a view reads only its own component already forces
  this: a parent reading `box.checked` would not be rebuilt when it changed. It also makes setting
  a value from code nothing more than assigning the parent's member. What the widget keeps is only
  what no parent cares about: whether the menu is open, the keyboard's row. The cost is a frame of
  latency between asking and being told, so two presses in one loop turn both read the old props;
  a widget remembers what it last asked for until its next view runs, which is after the parent
  answered. The test of two arrow keys in one turn is what found this.
- **Focus is a property of a pressable**, `pressable_t{ui::focusable}`. A press focuses it; Tab and
  Shift+Tab walk the focusable boxes in hit-test order, which is drawing order and so the order a
  view lists them in. The focused pressable is also a `source_t<key_event_t>` and is sent every key,
  Tab included, before focus moves -- a combobox closes on it. Space holds and then presses it, so a
  widget that reacts to presses works from the keyboard without code of its own. `focus_visible()`
  is set by a key and cleared by a click, for a ring only keyboard users see. Focus is dropped when
  its box leaves the hit-test list, so a disabled button cannot be pressed with Space.
- **A popup is a mount flag**, `ui::mount(menu).on_top(dismiss)`. It is placed where its parent puts
  it but takes no room there, always holds its own chunk, and is drawn and hit-tested after
  everything else, moved to fit the window. With a dismiss source, a whole-window hit-test entry
  sits under it, so a press outside reaches that source and nothing under it. Being a mount means
  the popup is its own component: the combobox creates its menu when it opens and drops it when it
  closes, shared through `mount_t::keep`, so the menu's row pressables outlive the frame in which
  the runtime still has them as hovered.
- **The keyboard's row and the pointer's are kept apart** in the menu: accent for the row Enter
  picks, a tint for the one under the pointer. Letting hover move the keyboard's row made a pointer
  that happened to rest where the menu opened take over the arrow keys.
- **A combobox is as wide as its widest option**, by drawing every option and its placeholder
  invisibly under the one shown, so it does not change width with the choice. The menu does the
  same with the placeholder; its padding adds up to the field's so both are the same width.

Not yet: a theme as props or inherited (one dark `theme_t` for now), type-to-search in a combobox,
flipping a menu above its field when there is no room below (it is moved up into the window
instead), focus that follows the pointer into a menu, and text input.

## G47. A live resize draws before WM_SIZE returns; what is left is the driver's

Content trailed the border while a window was dragged larger on Windows. Traced on an RX 5700 XT,
Release, dragging `vio_gui_ui_widgets` by its right edge:

- **Every other resize was drawn a refresh late.** `WM_SIZE` ran one nested turn, but a UI's frame
  loop waits on its own change signal, which wakes through the loop's deferred queue, and a turn
  drains that queue before the hook that hands out frames. So the frame for a new size was often
  only reached on the next turn -- the next `WM_TIMER`, about 16 ms later -- after Windows had
  already shown the window at that size. 50 of 80 frames were drawn inside `WM_SIZE`. Now
  `WM_SIZE` and `WM_PAINT` run turns until a frame has been taken or none is due, at most three:
  73 of 74, the other being the first frame.
- **A resize costs a new swapchain, and that is the driver's time:** `vkCreateSwapchainKHR` took a
  median 8.4 ms, against under 0.3 ms for everything else in a frame. Vulkan on Win32 requires the
  image size to equal the window's, so there is no reusing a larger one. Asking for the minimum
  image count made creation 5.5 ms but acquire then waited for vertical blank, 15 ms in all.
- **Present mode stays FIFO.** IMMEDIATE and MAILBOX (the latter not offered by this driver)
  showed more stretched frames mid-drag, not fewer.

What is left: a frame presented through a Vulkan swapchain reaches the screen on its own schedule,
not in the same composition as the border Windows moves, and while it is late Windows shows the
previous image stretched to the new size. `VK_EXT_swapchain_maintenance1` can ask for that image
to be shown unscaled at the top left instead, which is how a GDI window looks while it is resized;
this driver does not offer it. Drawing in step with the border needs DXGI with DirectComposition,
the D3D12 backend of phase 12. Mid-drag screen captures did not separate the builds before and
after the first fix -- a GDI capture does not sample what DWM shows at a given refresh -- so the
evidence for it is the trace above, not a picture.

## G48. The gui uses vio's public API only

The gui used to reach into `vio::detail` for six things: watching the display server's descriptor,
handing the blocking step to a Win32 or Cocoa message pump, before-block hooks, the deferred queue,
intrusive timers and the loop clock. Two of those had public equivalents (`timer_t`, `loop_now`).
The other four were capabilities vio did not expose, and are public now: `fd_watch_t` and
`host_loop.h` (core D57), `before_block_hook_t` and `deferred_call_t` (core D58). The rule matters
because the gui is moving to a repository of its own, where an internal header is one vio may
change without notice.

Display teardown is shorter for it. The gui's private fd watch was owned by the display, so the
display could not be freed until the watch's close had finished on a later turn, and every backend
reported that through a completion. A `vio::fd_watch_t` keeps its storage until vio is done with
it, and no callback arrives once the handle is dropped, so a backend's `close()` drops its watches
and returns, and the display is freed one posted turn later.
