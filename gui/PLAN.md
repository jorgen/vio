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

auto read_keys = [](vio::gui::window_t &window) -> vio::task_t<void> {
  auto keys = window.subscribe<vio::gui::key_event_t, vio::gui::text_event_t>();
  while (auto event = co_await keys)
    handle(*event);
}(*window);

auto wait_close = [](vio::event_loop_t &loop, vio::gui::window_t &window) -> vio::task_t<void> {
  auto requests = window.subscribe<vio::gui::close_request_t>();
  co_await requests;
  window.close();
  loop.stop();
}(loop, *window);

loop.run();
```

`frame()` works like `requestAnimationFrame`: each await asks for one frame, and it resolves at
the next point the display can show one. Awaiting it in a loop renders continuously; awaiting it
only after a change renders on demand. A window that was exposed or resized resolves the next
await at once.

Everything else a window reports is read through subscriptions: input, `resize_event_t` and
`close_request_t`, the alternatives of `window_event_t`. `subscribe<Ts...>()` names the types it
wants and yields `std::optional<T>` for one type, `std::optional<std::variant<Ts...>>` for several,
and every window event for `subscribe<>()`. Each subscription has its own queue: every one sees
every matching event that arrives after it was made, independently of the others, in order. An
event of a type nobody subscribed to is not kept. A pointer move, resize or close request that
arrives straight after another of its kind replaces it, so a burst of sizes reaches a reader as
the latest one. A close request leaves the window open until the program closes it.

Every await, a frame or a subscription, yields `std::nullopt` once the window has closed, so
`while (auto event = co_await keys)` and `while (auto frame = co_await window.frame())` end
exactly then.

## Examples

`gui/examples/`, each built as `vio_gui_<name>`. Each takes an optional limit (frames or
milliseconds) and quits after it, which is how CI runs them.

| example | shows |
|---------|-------|
| `hello_window` | a GL context, keys, clicks, resize and close in five coroutines |
| `input_echo` | every input event through three typed subscriptions, cursor shapes, clipboard copy and awaited paste |
| `windows_and_network` | two windows and a TCP server on one loop; text that arrives over TCP becomes the window titles |
| `vulkan_clear` | an instance from `required_instance_extensions`, a surface, a swapchain rebuilt on resize, and the device UUID CUDA matches |
| `metal_clear` | a `CAMetalLayer` from `metal::create_layer`, cleared every frame (macOS) |
| `d3d12_clear` | a swap chain from `d3d12::create_swap_chain`, resized with the window, and the adapter LUID CUDA matches (Windows) |

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

## UI toolkit

A declarative toolkit on top of the window layer, in `vio/gui/ui/ui.h` and `src/ui.cpp` as its own
target, `vio_gui_ui`, so the window layer stays free of any toolkit. Phase 6 is in;
`examples/ui_counter.cpp` and `test/test_ui.cpp` show it. It is not immediate mode. A UI is described with
struct literals, and its behaviour is coroutines awaiting events.

### Components

A component is one struct that holds its state, a `view()` that describes it, and an optional
`behave()` that reacts to events. There is no separate model or controller.

```cpp
struct counter_t
{
  int count = 0;
  ui::pressable_t inc, dec;

  ui::node_t view() const
  {
    return ui::row_t{.gap = 8, .children = {
      ui::box_t{.size = {60, 60}, .color = dec.held() ? dark_red : red, .events = dec},
      ui::box_t{.size = {60, 60}, .color = green, .events = inc},
      ui::box_t{.size = {20.f * count, 60}, .color = grey},
    }};
  }

  ui::behaviour_t behave(ui::scope_t &scope)
  {
    auto presses = ui::subscribe<ui::press_event_t>(inc, dec);
    while (auto press = co_await presses)
      count += press->source == &inc ? 1 : -1;
  }
};

co_await ui::run(*window, counter_t{});
```

`view()` is `const`: it describes and never mutates. `behave()` runs once, for the life of the
component, and keeps its state in ordinary members. React's hooks, stale closures and effect
dependencies all exist because a function component re-runs. Here only the stateless half
re-runs. A one-line handler can sit in the literal as a plain callback in `on_press`. Since the
view is const, its `this` is too, so for now such a handler has to `const_cast` to mutate its
component; a better spelling is open. Logic that spans several events, such as a drag, a
press-and-hold, or a press that waits for a reply, belongs in `behave()`.

The node types are plain aggregates, so a tree is written with designated initializers. The
recursion is legal because `std::vector` accepts an incomplete type:

```cpp
struct node_t;
struct box_t    { extent_t size; color_t color; event_ref_t events; ...; edges_t padding;
                  align_t align_x, align_y; std::vector<node_t> children; };
struct row_t    { int gap = 0; align_t align; edges_t padding; std::vector<node_t> children; };
struct column_t { int gap = 0; align_t align; edges_t padding; std::vector<node_t> children; };
struct node_t : std::variant<box_t, row_t, column_t, mount_t, text_t, icon_t, at_t, polyline_t> { ... };
```

**Layout** (G41) is content-sized and one pass, children first: nothing hands a child a size to
fill. A row or column lays its children along it with `gap`, inside `padding`, and places each
across by `align` -- start, center, end, or for a row baseline, which lines up the first text
baseline of each child to the pixel. A box with children holds them inside its padding, aligned by
`align_x` and `align_y`, overlapping; its `size` is then a minimum, which is how a label sits centred
on a button. `at_t` places its children at an offset that may be fractional, which is what lets a
plot's bars scroll smoothly. Positions are `float` throughout; hit testing rounds them.

**Flex** (G42): a node may be given a size by its parent. A row or column shares what is left along
it between children with `grow` (boxes, rows, columns, and `spacer_t`), and `align_t::stretch`
gives each child its whole breadth; a box stretches its children with `align_x`/`align_y`. The root
is given the window. Only a container that hands out space measures its children first -- placed
and taken back, cached per frame -- so the rest stays one pass. A mounted child is laid out for
what it was given, and laid out again only when that changes. Not yet: shrinking below the natural
size, or wrapping.

Field order is API, since designated initializers must follow it.

### Two trees

- The **component tree** is retained. `ui::run` owns the root, children are members of their
  parent, and `ui::list_t<T>` holds dynamic children at stable addresses. Identity is that stable
  ownership, so there are no reconciliation keys and no diffing. Interaction state (hovered, held,
  focused) lives in the event source, for example `pressable_t`, which a view may read.
- The **node tree** is disposable. Each component caches its last `view()` output. A
  `ui::mount(child)` in that output is a reference to the child component, not the child's nodes.

At a frame, only dirty components re-run `view()`. A parent that re-runs mounts the same child
again and does not rebuild it. Layout and drawing walk the stitched result and are whole-window
to begin with.

**A `view()` reads only its own component's state.** A parent that reads `left.count` is not
rebuilt when `left` changes, and nothing reports the stale frame. Data flows down as props,
`ui::mount(left, {.highlight = selected == 0})`: those props are part of the parent's output, and
the child is rebuilt when they compare unequal. Data flows up as events: the child exposes a
source and the parent's behaviour subscribes to it.

### Invalidation

`behave()` returns `ui::behaviour_t`, whose promise has an `await_transform`. Every `co_await`
in a behaviour, whether a UI event, `vio::sleep`, a socket read or a QUIC stream, is wrapped, and
the wrapper marks the component dirty when the coroutine resumes. The rule is: **a behaviour that
woke up rebuilds its view.** Being dirty only calls `request_frame()`, so ten wake-ups in one
turn cost one rebuild, done at the frame.

The gap: a nested `vio::task_t` that mutates the component mid-way is not seen until it returns
to the behaviour. `scope.invalidate()` covers that, and changes made from outside a behaviour.

### Behaviours and scopes

A scope is the lifetime of a component. `behave()` is the first behaviour started in it, and
`scope.spawn(b)` starts more. All of them run on the loop thread, so they share the component's
members without locks.

- The promise constructor takes the coroutine's arguments, so it finds `*this` and the
  `scope_t &` there before the body runs. A behaviour without a scope parameter does not compile.
- `behaviour_t` is lazy, unlike `task_t`. `spawn` takes the handle, records it and resumes it at
  once. The child runs to its first suspension before `spawn` returns.
- The scope owns the frames. A finished behaviour moves itself to the scope's finished list at
  `final_suspend`, and the scope destroys it in the beat, never from inside its own stack.
- A spawned behaviour belongs to the scope, not to its spawner, so it outlives a `behave()` that
  returns. A `scope_t` constructed from a parent is a child scope for shorter lifetimes, with
  `cancel()` and `co_await join()`, and the parent's cancellation reaches it.
- `spawn` returns `spawned_t<T>`, which can be awaited for the result. Dropping it does not
  detach the behaviour.
- An exception in a behaviour terminates, as it does in `task_t`. Keeping it in the promise and
  rethrowing it out of `ui::run`, the way a throwing callback leaves `run()` (D52), is still to do.

### Unmount and cancellation

`vio::cancellation_t` (`src/vio/cancellation.h`) shapes this part, in four ways:

- **A token reaches an operation only when the operation is created.** Sleep, DNS, file work,
  TCP connect/write/listen, TLS connect/handshake/write, UDP send, the QUIC operations and
  `http_client` fetch all take a `cancellation_t *` argument. Readers (`tcp_reader_t`,
  `stream_reader_t`, the UDP and QUIC stream readers) take none and have a `cancel()` method
  instead. The window's `frame()` and subscriptions take neither; they end when the window
  closes. So `await_transform` cannot attach cancellation to an operation that already exists.
  A behaviour passes `scope.token()` to what it starts, and binds a reader with
  `scope.bind(reader)`, which registers a callback calling `reader.cancel()`. The
  `registration_t` is RAII and deregisters when the frame is destroyed.
- **Some operations resume inside `cancel()`.** Sleep's callback calls `continuation.resume()`
  directly, while the QUIC operations latch and resume in the beat. So `scope.cancel()` can run
  behaviours on its own stack. It is called only from the beat, never while the framework walks
  the component tree or a scope's lists, and no frame is destroyed until it has returned.
- **A frame parked inside an operation is never destroyed,** because the operation holds its
  handle. Only a frame stopped at the wrapper's refusal (below) is destroyed. A parked operation
  that took no token therefore delays the unmount until it completes. That is correct, only late,
  like the TCP linger (D49).
- `cancellation_t` cannot be moved, so `scope_t` cannot either. It lives in the slot the
  framework holds for the component. A child scope registers a callback on its parent's token.

The unmount itself:

1. The component leaves the tree, because a parent stopped mounting it or a `list_t` erased it.
   It moves to a dying list and is not freed.
2. In the beat, the scope's token is cancelled. Operations holding it resolve as cancelled, bound
   readers are cancelled, and subscriptions on the component's sources yield `std::nullopt`.
3. Each behaviour resumes and runs to its next `co_await`. There, the wrapper's `await_suspend`
   sees the cancelled scope and does not arm the operation. The coroutine stays suspended with no
   one else holding its handle, and the scope destroys the frame after `cancel()` returns. Locals
   are destroyed with the frame, so a socket held in one closes. A `while (true)` loop around a
   sleep therefore ends without checking anything.
4. The component's storage is freed once its scope has no running behaviours, because every
   behaviour holds `this`.

Open question for vio: giving readers a `cancellation_t *` as well would make the token the only
mechanism and retire `scope.bind`.

### Several events at once

- **Several sources of one kind:** `ui::subscribe<press_event_t>(inc, dec)` reports which one
  fired, as `window.subscribe<A, B>()` reports which type arrived.
- **Independent concerns:** `scope.spawn` one straight-line loop per concern. This should be the
  common case.
- **First of several:** `ui::merge(a, b, c)` yields a variant from whichever source has
  something. It is over *sources*, things that queue the way subscriptions do, never over one-shot
  operations: a one-shot operation that loses the race must either be cancelled, which can drop
  what it already read, or carried into the next iteration and armed twice. Timers and sockets
  join through adapters (`ui::every`, `ui::lines`) that keep one operation armed and hold its
  result until it is taken.

### Input and drawing

Layout produces a flat list of `draw_item_t`, one per box. Hit testing walks that list backwards on
the window's pointer events, which arrive in the window system's units and are converted to layout
units first. A press is a down and an up on the same source, with the pointer captured between
them. Hit testing also sets hovered and held. Drawing reads a separate display list, below.

Layout is fixed sizes and row/column stacking. Flex-style grow and shrink comes next. Text is phase
10.

### Rendering

The renderer reads the display list and never reaches into the component layer. Phases 9 and 10,
and the first slice of 11, built what this section describes except where it says otherwise; G24-G41
hold the reasons.

**Two lists, not one.** `draw_item_t` stays what it is: one entry per hit-testable box, walked
backwards for input. Layout also emits a `display_list_t` in painter's order, which is what the
renderer consumes. They differ because one text item will be many glyphs and one plot thousands of
segments, none of which hit testing should walk (G24). Not yet: a clip rect per command, which
scrolling regions and plot areas will need.

**What a frame does** (G29), in `runtime_t::step`:

1. `build` re-runs the dirty views and marks `subtree_dirty` on the way back up through its return
   values, so an ancestor is marked without its view running. It still walks every slot to find
   which ones left the tree; that walk is pointer chasing, not views.
2. `lay_out` revisits only marked slots. Each lays out its marked children, then places its own
   output around them in one pass, producing its *entries*: primitives in its own coordinates and
   children at offsets. A clean slot keeps its size and entries. There are no constraints yet --
   sizes are fixed -- so a slot's size depends on its output and its children only; flex will add
   the constraints to what the cache depends on.
3. Chunks. The root always holds one; any other subtree holds one from `chunk_threshold` primitives
   (128 by default) and gives it back below half of that. A holder flattens its own entries and
   those of every non-holding descendant into one array, cut into segments wherever a holding
   descendant sits in painter's order. Only marked holders flatten again; a clean one is reused.
   Every primitive lives in one chunk, so memory is at most twice the primitives.
4. Assembly copies the chunks into one array and records a `run_t` per segment: a range and the
   origin it is drawn at. Moving a chunk changes its origin and nothing in it.
5. The hit-test list is rebuilt from the entries, with no view run.

So per frame the work that scales with the whole window is a pointer walk, one copy of every
primitive, and one walk of the boxes for hit testing; `view()`, layout and flattening scale with
what changed. Not yet: boundaries, subtrees that keep their own GPU buffer so that even the copy is
skipped (G29). They wait for a profile that asks for them -- plots are the likely first.

**Units** (G35). Layout is in logical units: `frame.framebuffer / frame.scale`, which is the
window's size on Wayland and macOS and its size divided by the UI scale on Windows and X11. The
renderer scales by framebuffer / logical. On a 144 DPI Windows display a 60-unit box is 90 pixels.

**One pipeline so far** (G26). One instanced quad per primitive, of four kinds (`prim_kind_t`). A
shape is computed per pixel: a rounded rectangle with per-corner radii and a border, or a blurred
one, which is a shadow (G37); a circle is a shape whose radii are half its size. Antialiasing is
half a pixel either side of the exact distance; no MSAA. Coverage -- a glyph or an icon -- is a
rectangle of the atlas copied texel for texel and tinted (G39). A segment is a line with round ends,
by its distance; an area is the region under one (G41). Colours are authored in sRGB and blended in
linear space (G38). Still to come: arcs in the same pipeline, and phase 11's point-buffer line
pipeline with joins that do not overlap (G28).

**Text** (G27, G39, G40). `text_t` is one line in one `font_t` at a size in logical units; a
`font_t` is a file's bytes and HarfBuzz's face over them, shared freely. Layout shapes it with
HarfBuzz and gets back its size and one coverage prim per inked glyph; FreeType rasterizes each at
size x scale pixels, light hinting, at one of four horizontal subpixel offsets, into an R8 atlas
keyed by font, pixel size, glyph and offset. All of a text's glyphs share one anchor, which the
shader rounds to a whole pixel, so the spacing HarfBuzz gave them survives any scale and any chunk
origin. A new scale empties the atlas and lays everything out again; so does an atlas that fills at
4096 square. `icon_t` is a `path_t` in a unit square, rasterized by FreeType's outline renderer
into the same atlas, so general paths are not needed on the GPU. Shaping runs where layout does,
so only for changed subtrees. Text with no font named uses `run_config_t::font`, else
`font_t::system_default()`. `src/ui_text.cpp` is all of it; nothing in `ui.h` names FreeType or
HarfBuzz. A text reports its baseline, a whole number of pixels below its anchor, which is what a
row aligned on baselines lines up. `tight` measures a text by its ink rather than its line, for a
symbol centred on a button (G41). Not yet: bidirectional text, font fallback, wrapping, colour
glyphs -- G40.

**Plots, first slice** (G41): `polyline_t` is a line through points in a box of a given size, with
round joins, an optional fill down to the box's bottom and optional round markers -- one segment
prim per segment, one area prim per segment of fill, one shape per marker, all through the one
pipeline. With rules, bars as boxes under `at_t`, and text for the labels, that is enough for the
scrolling line, bar and scatter plots in `vio_gui_ui_counter`. The plot rebuilds its prims whenever
its data changes; that is a few thousand prims and fine at UI rates, and it is what the rest below
replaces.

**Plots, the rest** (G28): polyline segments expanded in the vertex shader from a point buffer with miter
joins (bevel past a limit), so translucent lines do not double-blend at joints; fills as triangle
strips; heatmaps as an `R32F` data texture plus a colormap lookup texture; series uploaded in plot
coordinates relative to a per-series origin subtracted in `double`, with pan and zoom as a uniform;
M4 decimation (first, last, min, max per pixel column) once a series has more points than pixels.

**Shaders** (G25, G33): `src/shaders/ui.slang` is the source. `src/shaders/ui_spirv.h` is the
compiled SPIR-V, committed, so building vio needs no shader compiler; `cmake --build <dir> --target
vio_gui_shaders` regenerates it. `-DVIO_GUI_FETCH_SLANG=ON` has cmake-dep fetch a prebuilt slangc
2026.21 for the host and the target uses that; otherwise it looks for `slangc` on `PATH`. The
header in the tree is slangc output (G33).

**Vulkan** (G30, G31, G34). `src/ui_vulkan.cpp`: the loader is opened at run time, Vulkan 1.0, a
classic render pass, an sRGB swapchain with FIFO present, two frames in flight, one host-visible
vertex buffer per frame. One `vkCmdDraw` per run, the run's origin pushed as a constant. The
renderer creates its own instance and device unless `run_config_t::vulkan_device` hands it the
program's. `run_config_t::api` picks Vulkan, GL or automatic (Vulkan, then GL), and `on_renderer`
reports which was chosen and why the others were not.

**GL** stays as the fallback (G32): the scissor-clear stopgap of G23, now reading the display list.
Corners are square; shadows, text and icons are skipped.

**Damage** (G36). An expose -- `expose_event_t`, new in the window layer -- wakes the frame loop,
and the frame that follows reuses every chunk and runs no view.

**The atlas on the GPU** (G39). The display list carries an `atlas_view_t`: the pixels, a
generation, and the rectangle changed since the previous list. Vulkan keeps one `R8_UNORM` image,
read with `OpImageFetch` (no sampler), and copies only the dirty rectangle through a per-frame
staging buffer before the render pass; a new generation, a grown atlas, or a frame that was skipped
is a whole upload.

**Backend seam.** Per graphics API the renderer needs about five operations: upload a buffer,
upload a texture region, set a scissor, draw instanced, present. It is not a general rendering
hardware interface and must not grow into one. APIs are loaded at run time as G6 has it.

**Verified so far.** Windows, MSVC, AMD Radeon RX 5700 XT: `test/test_ui_render.cpp` (display list,
chunks, hysteresis, expose, and an offscreen Vulkan render read back pixel by pixel), and
`vio_gui_ui_counter` drawn through the swapchain at 144 DPI and checked by a screen capture. The
chunk-hysteresis and expose tests were each confirmed to fail with their fix reverted. Phase 10:
`test/test_ui_text.cpp` -- Devanagari reordering and Arabic joining from HarfBuzz's own test fonts,
a label and an icon at 1x and 2x, an atlas filling and emptying, and two offscreen renders, one of
which draws a glyph that reaches the GPU only through a dirty rectangle (confirmed to fail with
partial uploads switched off). `vio_gui_ui_counter` now shows labels, a star icon and a line of
Arabic, captured at 144 DPI; that capture is what found the barrier problem in G39, which no test
reproduces. **Not run:** Linux (lavapipe, X11, Wayland) and macOS (MoltenVK) -- Docker was down;
clang-cl `-fsyntax-only` over the phase 9 sources is the only check beyond MSVC. No validation
layer is installed on the machine that ran this, so `VIO_VULKAN_VALIDATION=1` checked nothing.
Layout and the first plots: `test/test_ui_layout.cpp` -- padding, alignment and growth of a box
around its children, rows and columns aligned across, a press on a label reaching its button,
`at_t`'s fractional offset, a polyline's prims and their order, and two offscreen renders: a line
over its fill, and three hundred areas a pixel wide at 1.5x on a fractional origin, every pixel
drawn once. The baseline test in `test_ui_text.cpp` runs at 1.5x and was confirmed to fail with the
shift rounded to whole units; the seam test was confirmed to fail with the areas overlapping by
0.6 px, and the thin-area test is what found the problem G41 describes, after the capture showed
stripes.

Open:

- Telling the compositor which region changed (`Present1` dirty rects,
  `VK_KHR_incremental_present`, Wayland damage) saves power, not frame time, and flip-model swap
  chains do not keep the previous frame. Deferred.
- A chunk is bounded per descendant, not in total: a parent of many small children holds one big
  chunk and flattens all of it on any change, and a holder flattens again when only a nested holder
  below it changed. G29 records both and the fix for each.
- Device loss is handled by giving up: `render` returns false and the frame loop stops drawing. A
  recreate would be better and is not written.
- The atlas never evicts: glyphs no longer shown stay until it fills at 4096 square and is emptied
  whole, which relays out everything once. Fine for UI text; a plot labelling at many sizes may want
  per-size eviction.
- A translucent polyline darkens where its segments overlap at each point (G41). Phase 11's joined
  segments (G28) fix it; until then plot lines are opaque.

## Phases

| phase | work | verified by |
|-------|------|-------------|
| 1 | host wait and nested turns in the vio core | core unit tests |
| 2 | display, window and awaited channels; X11 and Wayland | tests under Xvfb and headless weston |
| 3 | EGL, GL and Vulkan surfaces on Linux; interop properties | tests under Xvfb and weston, llvmpipe and lavapipe |
| 4 | Win32 backend, WGL and Direct3D 12 | Windows CI |
| 5 | Cocoa backend, NSOpenGL and Metal | macOS CI |
| 6 | UI: components, `behaviour_t` with dirty marking, scopes with `spawn` and unmount cancellation, `box`/`row`/`column`, mount, hit testing, scissor-clear drawing | a counter and a sleep-driven clock example; unit tests for scope teardown |
| 7 | UI: `list_t`, props, child scopes, `spawned_t<T>`; flex. **In on Windows** (G42) | a dynamic list example; unmount tests |
| 8 | UI: `merge` and the source adapters | a component mixing presses, a timer and a socket |
| 9 | Renderer: display list with per-slot commands, dirty propagation and chunks, cached layout, logical-unit layout, Slang shaders, the primitive pipeline on Vulkan, damage repaint. **In on Windows**; Linux and macOS not yet run | rounded rects, borders and shadows on screen; an expose with no change repaints |
| 10 | Text: FreeType and HarfBuzz through cmake-dep, glyph atlas, label component, icons. **In on Windows**; Linux and macOS not yet run | labels at 1x and 2x scale; a shaping test with a non-Latin script |
| 11 | Plots: polylines with joins, mesh pipeline, markers, heatmaps, M4 decimation. **First slice in on Windows** (G41): round-joined segments, area fills, markers | thick translucent zigzag lines; a million-point series panned at frame rate |
| 12 | D3D12 and Metal backends | the phase 9 to 11 examples on each |
