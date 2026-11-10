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
struct box_t    { extent_t size; color_t color; event_ref_t events; };
struct row_t    { float gap = 0; std::vector<node_t> children; };
struct column_t { float gap = 0; std::vector<node_t> children; };
struct node_t : std::variant<box_t, row_t, column_t> { using variant::variant; };
```

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

Layout produces a flat list of `{rect, color, source}`. Hit testing walks that list backwards on
the window's pointer events. A press is a down and an up on the same source, with the pointer
captured between them. Hit testing also sets hovered and held. The first renderer draws each box
with `glScissor` and `glClear`, which needs no shaders, no buffers and no linked graphics API,
only the `proc<>` lookups. A real renderer replaces it later, behind the same flat list.

Redraws follow invalidation and resizes only, so a damage-only expose is not repainted until
something changes (G23). Layout is fixed sizes and row/column stacking. Flex-style grow and shrink comes next. Text needs a
real renderer and a font dependency, and stays out until then.

### Rendering

The renderer replaces the scissor-clear stopgap at the layout output and never reaches into the
component layer. The design below is agreed in outline; G24-G28 hold the reasons.

**Two lists, not one.** `draw_item_t` stays what it is: one entry per hit-testable box, walked
backwards for input. Layout also emits a *display list* in painter's order, which is what the
renderer consumes. They differ because one text item is many glyphs and one plot is thousands of
segments, none of which hit testing should walk (G24). Each display-list command carries a clip
rect, so scrolling regions and plot areas clip by scissor.

**Incremental updates** (G29). `view()` is already incremental; layout and the display list
become so with the renderer:

- Each slot keeps the commands from its own output, in coordinates relative to its origin, and
  two flags. `view_dirty` re-runs its `view()`. `subtree_dirty` says something below changed. It
  is set on every ancestor up to the first that already has it, and never re-runs an ancestor's
  view. Assembly skips every subtree whose `subtree_dirty` is clear.
- Commands are grouped in *chunks*, so assembly is a few large copies rather than one tiny copy per
  component. A subtree with fewer than a threshold of commands (128 to start, to be tuned) is
  flattened into the chunk of its nearest ancestor that holds one. A chunk-holding subtree that
  falls below half the threshold folds back into its parent; the gap keeps a subtree near the
  limit from switching every frame. A change rebuilds only the chunk it lands in, from the
  retained per-slot commands, without running any clean view. Every command lives in exactly one
  chunk, so memory is at most twice the commands, never one copy per level of depth.
- A *boundary* is the other end of the same scale: a subtree large enough, or marked with
  `ui::boundary`, to own a persistent GPU instance buffer and its own draw call. A clean boundary
  costs no walk, no copy and no upload. Plots and long lists are the intended cases. Boundaries
  come when profiling asks for them; chunks and the dirty flags come with the renderer.
- Offsets are applied in the shader: each instance carries an index into a buffer of chunk
  origins, so copying a chunk is a plain `memcpy` and a chunk or boundary that only moved changes
  one origin and nothing else.
- Each slot caches its measured size and the constraints it was measured under. A clean slot under
  unchanged constraints answers from the cache without walking its subtree, and a dirty one whose
  size did not change stops the relayout there. This also ends today's repeated measuring, where
  `place` calls a recursive `measure` for every child.
- The whole window is rendered every frame: a GPU frame is not drawn in parts. Outside
  boundaries, the instance buffer is assembled from the chunks every frame. That is a copy of tens of
  microseconds for ten thousand primitives; the cost worth caching is `view()`, layout and shaping.
  The glyph atlas, plot point buffers and heatmap textures are persistent resources that commands
  refer to by handle, updated only when their data changes.
- Hit testing keeps `draw_item_t`, rebuilt from cached positions without running any view.
- Telling the compositor which region changed (`Present1` dirty rects,
  `VK_KHR_incremental_present`, Wayland damage) saves power, not frame time, and flip-model swap
  chains do not keep the previous frame. It is deferred.

**Units.** Layout is in logical units and the renderer works in framebuffer pixels as floats,
snapping rect edges to whole pixels itself. Today `step(frame->size)` lays out in the window
system's units (G9), which are pixels on Windows and X11, so the UI is not DPI-scaled there. The
renderer's arrival is when layout moves to `frame.size / frame.scale` on every platform.

**Two pipelines** (G26):

1. *Instanced primitives*: one quad per primitive, the shape evaluated analytically in the fragment
   shader -- rect, rounded rect with per-corner radii and border, analytic Gaussian shadow, circle,
   arc, capsule, plot marker, polyline segment, and atlas glyph. Antialiasing is
   `clamp(0.5 - d / fwidth(d), 0, 1)`; no MSAA.
2. *Triangle meshes*: fills that are not one of the primitives, such as the area under a plot
   curve.

Glyphs share the primitive pipeline, so text and shapes interleave in painter's order without a
pipeline change, and a typical window is one or two draws.

**Text** (G27): HarfBuzz shapes, FreeType rasterizes at the exact pixel size into a coverage atlas
keyed by font, size, glyph and one of four horizontal subpixel offsets. Blending is in linear
space. Icons are FreeType outline renders of vector paths into the same atlas, so general paths are
not needed on the GPU.

**Plots** (G28): polyline segments expanded in the vertex shader from a point buffer with miter
joins (bevel past a limit), so translucent lines do not double-blend at joints; fills as triangle
strips; heatmaps as an `R32F` data texture plus a colormap lookup texture; series uploaded in plot
coordinates relative to a per-series origin subtracted in `double`, with pan and zoom as a uniform;
M4 decimation (first, last, min, max per pixel column) once a series has more points than pixels.

**Shaders** (G25): Slang, compiled offline to SPIR-V, MSL and DXIL. The outputs are committed and
embedded with cmakerc, so building vio needs no `slangc`; a target regenerates them.

**Backend seam.** Per graphics API the renderer needs about five operations: upload a buffer,
upload a texture region, set a scissor, draw instanced, present. It is not a general rendering
hardware interface and must not grow into one. APIs are loaded at run time as G6 has it.

**Vulkan first** (G30). D3D12 and Metal follow in phase 12.

**Damage.** The present path closes G23's gap: a frame with `frame.damaged` set and nothing
invalidated re-submits the last display list without running layout. The frame loop has to learn
of damage while it waits on `changed()`, which today it does not.

Open:

- Who owns the device. The window layer never creates a device (see *Rendering contexts*); the
  renderer has to, by default, and should accept the program's when the program renders too.
- Whether GL stays as a backend once one of the three lands, or the stopgap is simply removed.

## Phases

| phase | work | verified by |
|-------|------|-------------|
| 1 | host wait and nested turns in the vio core | core unit tests |
| 2 | display, window and awaited channels; X11 and Wayland | tests under Xvfb and headless weston |
| 3 | EGL, GL and Vulkan surfaces on Linux; interop properties | tests under Xvfb and weston, llvmpipe and lavapipe |
| 4 | Win32 backend, WGL and Direct3D 12 | Windows CI |
| 5 | Cocoa backend, NSOpenGL and Metal | macOS CI |
| 6 | UI: components, `behaviour_t` with dirty marking, scopes with `spawn` and unmount cancellation, `box`/`row`/`column`, mount, hit testing, scissor-clear drawing | a counter and a sleep-driven clock example; unit tests for scope teardown |
| 7 | UI: `list_t`, props, child scopes, `spawned_t<T>` | a dynamic list example; unmount tests |
| 8 | UI: `merge` and the source adapters | a component mixing presses, a timer and a socket |
| 9 | Renderer: display list with per-slot commands, dirty propagation and chunks, cached layout, logical-unit layout, Slang shaders, the primitive pipeline on Vulkan, damage repaint | rounded rects, borders and shadows on screen; an expose with no change repaints |
| 10 | Text: FreeType and HarfBuzz through cmake-dep, glyph atlas, label component, icons | labels at 1x and 2x scale; a shaping test with a non-Latin script |
| 11 | Plots: polylines with joins, mesh pipeline, markers, heatmaps, M4 decimation | thick translucent zigzag lines; a million-point series panned at frame rate |
| 12 | D3D12 and Metal backends | the phase 9 to 11 examples on each |
