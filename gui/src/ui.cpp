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

#include "vio/gui/ui/ui.h"

#include <cmath>
#include <string>
#include <unordered_map>

#include <vio/event_loop.h>

#include "ui_renderer.h"
#include "ui_text.h"
#include "vio/gui/context.h"

namespace vio::gui::ui
{
namespace detail
{
using vio::detail::loop_core_t;
using vio::detail::posted_t;

// One laid-out piece of a component's own output: a primitive in the component's coordinates, or a
// mounted child placed at an offset. `box` is set on the primitive that draws a box, which is what
// hit testing reports; a shadow's primitive has none.
struct entry_t
{
  prim_t prim;
  slot_t *child = nullptr;
  const box_t *box = nullptr;
  float x = 0;
  float y = 0;
  int ordinal = 0;
};

// A chunk is the flattened output of a subtree too small to keep apart (G29): its own primitives
// and its inlined descendants', in its own coordinates, cut into segments wherever a descendant
// large enough to hold a chunk of its own sits in painter's order.
struct segment_t
{
  std::uint32_t begin = 0;
  std::uint32_t end = 0;
  slot_t *child = nullptr;
  float x = 0;
  float y = 0;
};

struct chunk_t
{
  std::vector<prim_t> prims;
  std::vector<segment_t> segments;
  bool valid = false;
};

// What the framework keeps for one mounted component.
struct slot_t
{
  void *component = nullptr;
  node_t (*view)(const void *) = nullptr;
  behaviour_t (*behave)(void *, scope_t &) = nullptr;
  std::unique_ptr<scope_t> scope;
  node_t output;
  // Its view must run again.
  bool dirty = true;
  // It or something below it changed since the last frame, so its layout, entries and chunk are
  // stale. Set on the way back up from a view that ran; never re-runs this slot's own view.
  bool subtree_dirty = false;
  bool reached = false;
  // Laid out at least once; until then it counts as changed.
  bool laid_out = false;

  extent_t size;
  std::vector<entry_t> entries;
  std::size_t subtree_prims = 0;
  bool holder = false;
  chunk_t chunk;
};

// Where a press is aimed. A box with a source is that source wherever it moves; a box with only an
// on_press handler is its place in its component's output, which survives a rebuild of the same
// shape.
struct target_t
{
  const pressable_t *source = nullptr;
  slot_t *slot = nullptr;
  int ordinal = -1;

  [[nodiscard]] bool empty() const noexcept
  {
    return source == nullptr && slot == nullptr;
  }
  friend bool operator==(const target_t &, const target_t &) = default;
};

namespace
{
prim_t box_prim(const box_t &box, float x, float y, extent_t size)
{
  prim_t prim;
  prim.x = x;
  prim.y = y;
  prim.width = float(size.width);
  prim.height = float(size.height);
  for (auto &radius : prim.radii)
    radius = box.radius;
  prim.fill = box.color;
  prim.border_color = box.border_color;
  prim.border_width = box.border_width;
  return prim;
}

bool has_shadow(const box_t &box) noexcept
{
  return box.shadow.color.a > 0 && (box.shadow.blur > 0 || box.shadow.x != 0 || box.shadow.y != 0);
}

prim_t shadow_prim(const box_t &box, float x, float y, extent_t size)
{
  prim_t prim = box_prim(box, x, y, size);
  prim.x += box.shadow.x;
  prim.y += box.shadow.y;
  prim.fill = box.shadow.color;
  prim.border_color = {0, 0, 0, 0};
  prim.border_width = 0;
  prim.blur = box.shadow.blur;
  return prim;
}

// Move a prim by (dx, dy). A segment's and an area's far ends are positions too. Every prim moves
// by the same additions, so two areas that share an x still share it bit for bit after any move.
void move_prim(prim_t &prim, float dx, float dy) noexcept
{
  prim.x += dx;
  prim.y += dy;
  if (prim.kind == prim_kind_t::segment)
  {
    prim.radii[0] += dx;
    prim.radii[1] += dy;
  }
  else if (prim.kind == prim_kind_t::area)
  {
    prim.radii[0] += dx;
    prim.radii[1] += dy;
    prim.radii[2] += dy;
  }
}

// The nodes inside a container, or null.
const std::vector<node_t> *children_of(const node_t &node) noexcept
{
  if (const auto *row = std::get_if<row_t>(&node))
    return &row->children;
  if (const auto *column = std::get_if<column_t>(&node))
    return &column->children;
  if (const auto *box = std::get_if<box_t>(&node))
    return &box->children;
  if (const auto *at = std::get_if<at_t>(&node))
    return &at->children;
  return nullptr;
}

// Where a child of `size` starts in `room`, by alignment. Baseline is resolved by the row itself.
int aligned(align_t align, int room, int size) noexcept
{
  switch (align)
  {
  case align_t::center:
    return (room - size) / 2;
  case align_t::end:
    return room - size;
  default:
    return 0;
  }
}
} // namespace

class runtime_t
{
public:
  runtime_t(window_t &window, run_config_t config)
    : _window(window)
    , _core(window.impl()->display.core)
    , _config(std::move(config))
  {
    _beat.owner = this;
    _beat.run = [](posted_t *node) { static_cast<runtime_t *>(node->owner)->beat(); };
    _finish.owner = this;
    _finish.run = [](posted_t *node) {
      auto *self = static_cast<runtime_t *>(node->owner);
      if (auto handle = std::exchange(self->_drained_waiter, {}))
        handle.resume();
    };
  }
  runtime_t(const runtime_t &) = delete;
  runtime_t &operator=(const runtime_t &) = delete;
  ~runtime_t()
  {
    _core.unpost(_beat);
    _core.unpost(_finish);
  }

  [[nodiscard]] vio::event_loop_t &loop() const noexcept
  {
    return *_window.impl()->display.loop;
  }

  [[nodiscard]] const run_config_t &config() const noexcept
  {
    return _config;
  }

  // ---- resumption: everything the toolkit resumes, it resumes here, from the loop's deferred
  // queue, so nothing it wakes runs on the stack of whatever recorded the event.
  void ready(waiter_t &waiter) noexcept
  {
    _ready.push_back(waiter);
    schedule();
  }
  void bury(std::coroutine_handle<> frame) noexcept
  {
    _dead.push_back(frame);
    schedule();
  }
  void schedule() noexcept
  {
    _core.defer(_beat);
  }

  void beat()
  {
    for (;;)
    {
      if (auto *waiter = _ready.pop_front())
      {
        waiter->handle.resume();
        continue;
      }
      if (!_dead.empty())
      {
        for (auto frame : std::exchange(_dead, {}))
          frame.destroy();
        reap();
        continue;
      }
      break;
    }
  }

  // ---- invalidation
  void invalidate(slot_t &slot) noexcept
  {
    slot.dirty = true;
    wake_frame();
  }
  void wake_frame() noexcept
  {
    _changed = true;
    if (_change_waiter.handle && !_change_waiter.list)
      ready(_change_waiter);
  }

  struct change_awaitable_t
  {
    runtime_t &runtime;
    [[nodiscard]] bool await_ready() const noexcept
    {
      return runtime._changed;
    }
    void await_suspend(std::coroutine_handle<> handle) noexcept
    {
      runtime._change_waiter.handle = handle;
    }
    void await_resume() const noexcept
    {
      runtime._change_waiter.handle = {};
    }
  };
  [[nodiscard]] change_awaitable_t changed() noexcept
  {
    return {*this};
  }

  // ---- the frame step: views that are dirty, layout and entries of the subtrees they are in, the
  // chunks those subtrees fall in; then the display list and the hit-test list, assembled whole.
  void step(const frame_t &frame)
  {
    _changed = false;
    // The renderer has drawn the previous list, so what it uploaded is no longer new.
    _text.clear_dirty();
    if (set_units(frame))
    {
      // Text is rasterized at its size in pixels, so a new scale lays everything out again.
      _text.set_scale(_scale);
      for (auto &[component, slot] : _slots)
        slot->laid_out = false;
    }
    if (!_root)
      _root = make_slot(_root_mount);
    for (auto &[component, slot] : _slots)
      slot->reached = false;
    build(*_root);

    std::vector<slot_t *> leaving;
    for (auto it = _slots.begin(); it != _slots.end();)
    {
      if (it->second->reached)
      {
        ++it;
        continue;
      }
      leaving.push_back(it->second.get());
      _dying.push_back(std::move(it->second));
      it = _slots.erase(it);
    }
    for (auto *slot : leaving)
      unmount(*slot);

    lay_out(*_root);
    if (_text.take_reset())
    {
      // The atlas filled and was emptied part way through: whatever was laid out before that names
      // rectangles that are gone. Once more, from an empty atlas (G39).
      for (auto &[component, slot] : _slots)
        mark(*slot);
      lay_out(*_root);
    }
    _prims.clear();
    _runs.clear();
    _root->holder = true;
    emit(*_root, 0, 0);
    for (auto *slot : std::exchange(_touched, {}))
      slot->subtree_dirty = false;

    _items.clear();
    collect_items(*_root, 0, 0);
    if (_has_pointer)
      hover(_pointer);
    if (_config.on_layout)
      _config.on_layout(_items);
    if (_config.on_display_list)
      _config.on_display_list(display_list());
  }

  [[nodiscard]] display_list_t display_list() const noexcept
  {
    return {_prims, _runs, _config.background, _logical, _framebuffer, _scale, _text.atlas()};
  }

  // ---- input. Pointer positions arrive in the window system's units (G9) and are kept in layout
  // units.
  void pointer_moved(point_t position)
  {
    _pointer = to_logical(position);
    _has_pointer = true;
    hover(_pointer);
  }
  void pointer_left()
  {
    _has_pointer = false;
    set_hovered(nullptr);
  }
  void button(const pointer_button_event_t &event)
  {
    if (event.button != button_t::left)
      return;
    const auto position = to_logical(event.position);
    _pointer = position;
    _has_pointer = true;
    hover(position);
    if (event.pressed)
    {
      _held = target_at(position);
      if (_held.source)
        set_flag(_held.source, &pressable_t::_held, true);
      return;
    }
    auto held = std::exchange(_held, {});
    if (held.source)
      set_flag(held.source, &pressable_t::_held, false);
    if (held.empty() || !(target_at(position) == held))
      return;
    const auto *item = find(held);
    if (held.source)
      const_cast<pressable_t *>(held.source)->emit(press_event_t{held.source, position}, *this);
    if (item && item->box->on_press)
    {
      // The handler mutates its component, so that component is rebuilt. Copied first: the
      // handler may invalidate, and nothing here rebuilds before it returns, but the copy keeps
      // that true however the handler is written.
      auto handler = item->box->on_press;
      auto *slot = item->slot;
      handler();
      invalidate(*slot);
    }
  }

  // ---- teardown
  void shutdown()
  {
    std::vector<slot_t *> leaving;
    for (auto &[component, slot] : _slots)
    {
      leaving.push_back(slot.get());
      _dying.push_back(std::move(slot));
    }
    _slots.clear();
    _root = nullptr;
    _items.clear();
    _prims.clear();
    _runs.clear();
    for (auto *slot : leaving)
      unmount(*slot);
    reap();
  }

  struct drained_awaitable_t
  {
    runtime_t &runtime;
    [[nodiscard]] bool await_ready() const noexcept
    {
      return false;
    }
    void await_suspend(std::coroutine_handle<> handle) noexcept
    {
      runtime._drained_waiter = handle;
      runtime.check_drained();
    }
    void await_resume() const noexcept
    {
    }
  };
  // Resolves once every scope has no behaviour left. Always suspends and is resumed from a node of
  // its own, never from inside beat(): what it resumes goes on to destroy this runtime.
  [[nodiscard]] drained_awaitable_t drained() noexcept
  {
    return {*this};
  }

  void set_root(mount_t root) noexcept
  {
    _root_mount = root;
  }

private:
  // Layout is in logical units: the framebuffer divided by the scale, which is the window's size on
  // Wayland and macOS and its size divided by the UI scale on Windows and X11 (G9).
  // Returns whether the scale changed.
  bool set_units(const frame_t &frame)
  {
    _framebuffer = frame.framebuffer;
    const float previous = _scale;
    _scale = frame.scale > 0 ? frame.scale : 1.0f;
    _logical = {int(std::lround(frame.framebuffer.width / _scale)), int(std::lround(frame.framebuffer.height / _scale))};
    _input_x = frame.size.width > 0 ? double(_logical.width) / frame.size.width : 1.0;
    _input_y = frame.size.height > 0 ? double(_logical.height) / frame.size.height : 1.0;
    return _scale != previous;
  }

  [[nodiscard]] point_t to_logical(point_t position) const noexcept
  {
    return {position.x * _input_x, position.y * _input_y};
  }

  slot_t *make_slot(const mount_t &mount)
  {
    auto slot = std::make_unique<slot_t>();
    slot->component = mount.component;
    slot->view = mount.view;
    slot->behave = mount.behave;
    slot->scope = std::make_unique<scope_t>(*this, slot.get());
    auto *raw = slot.get();
    _slots.emplace(key_of(mount), std::move(slot));
    if (raw->behave)
      raw->scope->spawn(raw->behave(raw->component, *raw->scope));
    return raw;
  }

  slot_t *slot_for(const mount_t &mount)
  {
    auto it = _slots.find(key_of(mount));
    return it == _slots.end() ? make_slot(mount) : it->second.get();
  }

  slot_t *existing(const mount_t &mount) const
  {
    auto it = _slots.find(key_of(mount));
    return it == _slots.end() ? nullptr : it->second.get();
  }

  // Re-run the views that are dirty, starting at `slot`, and mark what is still mounted. Returns
  // whether anything at or below `slot` changed, which is what marks it subtree_dirty: the mark
  // travels up through the return values and never re-runs a view.
  bool build(slot_t &slot)
  {
    slot.reached = true;
    bool changed = false;
    if (slot.dirty)
    {
      slot.dirty = false;
      slot.output = slot.view(slot.component);
      changed = true;
    }
    if (visit_mounts(slot.output))
      changed = true;
    if (changed || !slot.laid_out)
      mark(slot);
    return slot.subtree_dirty;
  }

  bool visit_mounts(const node_t &node)
  {
    if (const auto *mount = std::get_if<mount_t>(&node))
    {
      auto *child = slot_for(*mount);
      return !child->reached && build(*child);
    }
    const std::vector<node_t> *children = children_of(node);
    bool changed = false;
    if (children)
    {
      for (const auto &child : *children)
      {
        if (visit_mounts(child))
          changed = true;
      }
    }
    return changed;
  }

  void mark(slot_t &slot)
  {
    if (slot.subtree_dirty)
      return;
    slot.subtree_dirty = true;
    _touched.push_back(&slot);
  }

  // ---- layout. A subtree that did not change keeps its size and its entries; one that did lays
  // its children out first and then places its own output around them, in one pass, since a row
  // or column needs each child's size only once it has been placed.
  void lay_out(slot_t &slot)
  {
    if (!slot.subtree_dirty)
      return;
    slot.entries.clear();
    slot.subtree_prims = 0;
    int ordinal = 0;
    slot.size = place(slot, slot.output, 0, 0, ordinal).size;
    slot.laid_out = true;
  }

  // What placing a node produced: its size, and its first baseline below its top if it has one.
  struct placed_t
  {
    extent_t size;
    float baseline = -1;
    [[nodiscard]] bool has_baseline() const noexcept
    {
      return baseline >= 0;
    }
  };

  // A child a container has placed at its start position: the range of entries it produced, so
  // that moving it into position reaches all of them.
  struct placed_child_t
  {
    std::size_t begin = 0;
    std::size_t end = 0;
    placed_t placed;
  };

  placed_child_t place_child(slot_t &slot, const node_t &node, float x, float y, int &ordinal)
  {
    placed_child_t child;
    child.begin = slot.entries.size();
    child.placed = place(slot, node, x, y, ordinal);
    child.end = slot.entries.size();
    return child;
  }

  void shift(slot_t &slot, const placed_child_t &child, float dx, float dy)
  {
    if (dx == 0 && dy == 0)
      return;
    for (std::size_t i = child.begin; i < child.end; ++i)
    {
      auto &entry = slot.entries[i];
      entry.x += dx;
      entry.y += dy;
      if (!entry.child)
        move_prim(entry.prim, dx, dy);
    }
  }

  // Layout is one pass, children first. A container places each child at its start position, and
  // moves it once its own size is known -- which is only once every child has been placed.
  placed_t place(slot_t &slot, const node_t &node, float x, float y, int &ordinal)
  {
    if (const auto *box = std::get_if<box_t>(&node))
      return place_box(slot, *box, x, y, ordinal);
    if (const auto *text = std::get_if<text_t>(&node))
    {
      const auto laid = _text.add_text(*text, default_font(), x, y, _glyphs);
      place_glyphs(slot);
      return {laid.size, laid.baseline};
    }
    if (const auto *icon = std::get_if<icon_t>(&node))
    {
      const auto size = _text.add_icon(*icon, x, y, _glyphs);
      place_glyphs(slot);
      return {size};
    }
    if (const auto *line = std::get_if<polyline_t>(&node))
      return place_polyline(slot, *line, x, y);
    if (const auto *at = std::get_if<at_t>(&node))
    {
      extent_t size;
      for (const auto &child : at->children)
      {
        const auto placed = place(slot, child, x + at->x, y + at->y, ordinal);
        size.width = std::max(size.width, int(std::ceil(at->x + float(placed.size.width))));
        size.height = std::max(size.height, int(std::ceil(at->y + float(placed.size.height))));
      }
      return {size};
    }
    if (const auto *mount = std::get_if<mount_t>(&node))
    {
      auto *child = existing(*mount);
      if (!child)
        return {};
      lay_out(*child);
      entry_t entry;
      entry.child = child;
      entry.x = x;
      entry.y = y;
      slot.entries.push_back(entry);
      slot.subtree_prims += child->subtree_prims;
      // A component's baseline is not kept between frames, so a mounted child has none.
      return {child->size};
    }
    if (const auto *row = std::get_if<row_t>(&node))
      return place_line(slot, row->children, true, row->gap, row->align, row->padding, x, y, ordinal);
    const auto &column = std::get<column_t>(node);
    return place_line(slot, column.children, false, column.gap, column.align, column.padding, x, y, ordinal);
  }

  placed_t place_box(slot_t &slot, const box_t &box, float x, float y, int &ordinal)
  {
    // The box is drawn before its children, so its entries go in first and are filled in once the
    // children have given it its size.
    const bool shadowed = has_shadow(box);
    if (shadowed)
    {
      slot.entries.push_back(entry_t{});
      ++slot.subtree_prims;
    }
    const std::size_t index = slot.entries.size();
    slot.entries.push_back(entry_t{});
    ++slot.subtree_prims;
    const int box_ordinal = ordinal++;

    const auto &pad = box.padding;
    std::vector<placed_child_t> children;
    children.reserve(box.children.size());
    extent_t content;
    for (const auto &node : box.children)
    {
      children.push_back(place_child(slot, node, x + float(pad.left), y + float(pad.top), ordinal));
      content.width = std::max(content.width, children.back().placed.size.width);
      content.height = std::max(content.height, children.back().placed.size.height);
    }
    const extent_t size{std::max(box.size.width, content.width + pad.left + pad.right), std::max(box.size.height, content.height + pad.top + pad.bottom)};
    const extent_t room{size.width - pad.left - pad.right, size.height - pad.top - pad.bottom};
    float baseline = -1;
    for (const auto &child : children)
    {
      const int dx = aligned(box.align_x, room.width, child.placed.size.width);
      const int dy = aligned(box.align_y, room.height, child.placed.size.height);
      shift(slot, child, float(dx), float(dy));
      if (baseline < 0 && child.placed.has_baseline())
        baseline = float(pad.top + dy) + child.placed.baseline;
    }

    if (shadowed)
      slot.entries[index - 1].prim = shadow_prim(box, x, y, size);
    auto &entry = slot.entries[index];
    entry.prim = box_prim(box, x, y, size);
    entry.box = &box;
    entry.x = x;
    entry.y = y;
    entry.ordinal = box_ordinal;
    return {size, baseline};
  }

  placed_t place_line(slot_t &slot, const std::vector<node_t> &nodes, bool horizontal, int gap, align_t align, const edges_t &pad, float x, float y, int &ordinal)
  {
    std::vector<placed_child_t> children;
    children.reserve(nodes.size());
    // Where each child starts along the line, from the content's edge.
    std::vector<int> starts;
    starts.reserve(nodes.size());
    int along = 0;
    for (std::size_t i = 0; i < nodes.size(); ++i)
    {
      if (i > 0)
        along += gap;
      starts.push_back(along);
      const float cx = x + float(pad.left + (horizontal ? along : 0));
      const float cy = y + float(pad.top + (horizontal ? 0 : along));
      children.push_back(place_child(slot, nodes[i], cx, cy, ordinal));
      const auto &size = children.back().placed.size;
      along += horizontal ? size.width : size.height;
    }

    int across = 0;
    float baseline = -1;
    if (horizontal && align == align_t::baseline)
    {
      // Above the shared baseline, the tallest ascent; below it, the deepest descent. A child with
      // no baseline stands on it. Text moves by a fraction of a unit here, and that is exact: each
      // baseline is a whole number of pixels below its anchor, so all of them land on one pixel row.
      const auto baseline_of = [](const placed_t &placed) { return placed.has_baseline() ? placed.baseline : float(placed.size.height); };
      float above = 0;
      float below = 0;
      for (const auto &child : children)
      {
        above = std::max(above, baseline_of(child.placed));
        below = std::max(below, float(child.placed.size.height) - baseline_of(child.placed));
      }
      for (const auto &child : children)
        shift(slot, child, 0, above - baseline_of(child.placed));
      across = int(std::ceil(above + below - 1e-3f));
      if (!children.empty())
        baseline = float(pad.top) + above;
    }
    else
    {
      for (const auto &child : children)
        across = std::max(across, horizontal ? child.placed.size.height : child.placed.size.width);
      for (std::size_t i = 0; i < children.size(); ++i)
      {
        const auto &child = children[i];
        const auto &size = child.placed.size;
        const int d = aligned(align, across, horizontal ? size.height : size.width);
        shift(slot, child, horizontal ? 0.0f : float(d), horizontal ? float(d) : 0.0f);
        if (baseline < 0 && child.placed.has_baseline())
          baseline = float(pad.top + (horizontal ? d : starts[i])) + child.placed.baseline;
      }
    }
    const extent_t content = horizontal ? extent_t{along, across} : extent_t{across, along};
    return {{content.width + pad.left + pad.right, content.height + pad.top + pad.bottom}, baseline};
  }

  // Areas first, so the line covers the antialiased top edge of its own fill; then the segments;
  // then the markers over both.
  placed_t place_polyline(slot_t &slot, const polyline_t &line, float x, float y)
  {
    const auto &points = line.points;
    const auto push = [&](const prim_t &prim)
    {
      slot.entries.push_back(entry_t{prim});
      ++slot.subtree_prims;
    };
    if (line.fill.a > 0)
    {
      const float bottom = y + float(line.size.height);
      for (std::size_t i = 1; i < points.size(); ++i)
      {
        if (!(points[i].x > points[i - 1].x))
          continue;
        prim_t prim;
        prim.kind = prim_kind_t::area;
        prim.x = x + points[i - 1].x;
        prim.y = y + points[i - 1].y;
        prim.radii[0] = x + points[i].x;
        prim.radii[1] = y + points[i].y;
        prim.radii[2] = bottom;
        prim.fill = line.fill;
        push(prim);
      }
    }
    if (line.width > 0 && line.color.a > 0)
    {
      for (std::size_t i = 1; i < points.size(); ++i)
      {
        prim_t prim;
        prim.kind = prim_kind_t::segment;
        prim.x = x + points[i - 1].x;
        prim.y = y + points[i - 1].y;
        prim.radii[0] = x + points[i].x;
        prim.radii[1] = y + points[i].y;
        prim.border_width = line.width;
        prim.fill = line.color;
        push(prim);
      }
    }
    if (line.marker > 0 && line.color.a > 0)
    {
      const float r = line.marker * 0.5f;
      for (const auto &point : points)
      {
        prim_t prim;
        prim.x = x + point.x - r;
        prim.y = y + point.y - r;
        prim.width = line.marker;
        prim.height = line.marker;
        for (auto &radius : prim.radii)
          radius = r;
        prim.fill = line.color;
        push(prim);
      }
    }
    return {line.size};
  }

  void place_glyphs(slot_t &slot)
  {
    for (const auto &prim : _glyphs)
      slot.entries.push_back(entry_t{prim});
    slot.subtree_prims += _glyphs.size();
    _glyphs.clear();
  }

  // The font for text that names none, looked up on first use.
  const font_t &default_font()
  {
    if (!_default_font && !_looked_for_font)
    {
      _looked_for_font = true;
      if (_config.font)
        _default_font = _config.font;
      else if (auto font = font_t::system_default())
        _default_font = std::move(*font);
    }
    return _default_font;
  }

  // ---- chunks (G29). The root always holds one. Any other subtree holds one from the threshold
  // up and gives it back below half of it, so a subtree near the limit does not switch every frame.
  bool decide_holder(slot_t &slot)
  {
    const std::size_t threshold = std::max<std::size_t>(_config.chunk_threshold, 1);
    const bool now = slot.holder ? slot.subtree_prims >= std::max<std::size_t>(threshold / 2, 1) : slot.subtree_prims >= threshold;
    if (now != slot.holder)
    {
      slot.holder = now;
      slot.chunk = {};
    }
    return now;
  }

  void flatten(slot_t &holder)
  {
    auto &chunk = holder.chunk;
    chunk.prims.clear();
    chunk.segments.clear();
    std::uint32_t begin = 0;
    auto close_run = [&] {
      const auto end = std::uint32_t(chunk.prims.size());
      if (end > begin)
        chunk.segments.push_back(segment_t{begin, end});
      begin = end;
    };
    auto walk = [&](auto &self, const slot_t &slot, float dx, float dy) -> void
    {
      for (const auto &entry : slot.entries)
      {
        if (!entry.child)
        {
          prim_t prim = entry.prim;
          move_prim(prim, dx, dy);
          chunk.prims.push_back(prim);
          continue;
        }
        if (decide_holder(*entry.child))
        {
          close_run();
          chunk.segments.push_back(segment_t{0, 0, entry.child, dx + entry.x, dy + entry.y});
          continue;
        }
        self(self, *entry.child, dx + entry.x, dy + entry.y);
      }
    };
    walk(walk, holder, 0, 0);
    close_run();
    chunk.valid = true;
  }

  // Concatenate the chunks into this frame's prims, one run per segment. A clean chunk is a copy.
  void emit(slot_t &holder, float x, float y)
  {
    if (holder.subtree_dirty || !holder.chunk.valid)
      flatten(holder);
    for (const auto &segment : holder.chunk.segments)
    {
      if (segment.child)
      {
        emit(*segment.child, x + segment.x, y + segment.y);
        continue;
      }
      const auto first = std::uint32_t(_prims.size());
      _prims.insert(_prims.end(), holder.chunk.prims.begin() + segment.begin, holder.chunk.prims.begin() + segment.end);
      _runs.push_back(run_t{first, segment.end - segment.begin, x, y});
    }
  }

  // The hit-test list, from the entries as they stand: no view runs for it.
  void collect_items(slot_t &slot, float x, float y)
  {
    for (const auto &entry : slot.entries)
    {
      if (entry.child)
      {
        collect_items(*entry.child, x + entry.x, y + entry.y);
        continue;
      }
      if (!entry.box)
        continue;
      const auto &box = *entry.box;
      const rect_t rect{int(std::lround(x + entry.x)), int(std::lround(y + entry.y)), int(entry.prim.width), int(entry.prim.height)};
      _items.push_back(draw_item_t{rect, box.color, &box, &slot, entry.ordinal});
    }
  }

  [[nodiscard]] const draw_item_t *hit(point_t position) const noexcept
  {
    for (auto it = _items.rbegin(); it != _items.rend(); ++it)
    {
      if (it->rect.contains(position) && (it->box->events.source || it->box->on_press))
        return &*it;
    }
    return nullptr;
  }

  [[nodiscard]] target_t target_at(point_t position) const noexcept
  {
    const auto *item = hit(position);
    if (!item)
      return {};
    if (item->box->events.source)
      return {item->box->events.source, nullptr, -1};
    return {nullptr, item->slot, item->ordinal};
  }

  [[nodiscard]] const draw_item_t *find(const target_t &target) const noexcept
  {
    for (const auto &item : _items)
    {
      if (target.source ? item.box->events.source == target.source : (item.slot == target.slot && item.ordinal == target.ordinal))
        return &item;
    }
    return nullptr;
  }

  // The slot whose view shows `source`, which is the one to rebuild when its state changes.
  slot_t *owner_of(const pressable_t *source) const noexcept
  {
    for (const auto &item : _items)
    {
      if (item.box->events.source == source)
        return item.slot;
    }
    return nullptr;
  }

  void set_flag(const pressable_t *source, bool pressable_t::*flag, bool value)
  {
    auto *mutable_source = const_cast<pressable_t *>(source);
    if (mutable_source->*flag == value)
      return;
    mutable_source->*flag = value;
    if (auto *slot = owner_of(source))
      invalidate(*slot);
  }

  void hover(point_t position)
  {
    const auto *item = hit(position);
    set_hovered(item ? item->box->events.source : nullptr);
  }

  void set_hovered(const pressable_t *source)
  {
    if (source == _hovered)
      return;
    if (_hovered)
      set_flag(_hovered, &pressable_t::_hovered, false);
    _hovered = source;
    if (source)
      set_flag(source, &pressable_t::_hovered, true);
  }

  void unmount(slot_t &slot)
  {
    if (_hovered && owner_of(_hovered) == &slot)
      _hovered = nullptr;
    if (_held.slot == &slot || (_held.source && owner_of(_held.source) == &slot))
      _held = {};
    std::erase(_touched, &slot);
    slot.scope->cancel();
  }

  // Free what has left the tree once nothing in it runs.
  void reap()
  {
    std::erase_if(_dying, [](const std::unique_ptr<slot_t> &slot) { return slot->scope->running() == 0; });
    check_drained();
  }

  void check_drained() noexcept
  {
    if (!_drained_waiter || !_dying.empty() || !_slots.empty())
      return;
    _core.defer(_finish);
  }

  window_t &_window;
  loop_core_t &_core;
  run_config_t _config;
  posted_t _beat;
  posted_t _finish;
  waiter_list_t _ready;
  std::vector<std::coroutine_handle<>> _dead;

  mount_t _root_mount;
  slot_t *_root = nullptr;
  // Keyed by address and type: a component and its first member share an address, never a view.
  struct key_t
  {
    void *component;
    node_t (*view)(const void *);
    friend bool operator==(const key_t &, const key_t &) = default;
  };
  struct key_hash_t
  {
    std::size_t operator()(const key_t &key) const noexcept
    {
      return std::hash<void *>()(key.component) ^ (std::hash<void *>()(reinterpret_cast<void *>(key.view)) << 1);
    }
  };
  static key_t key_of(const mount_t &mount) noexcept
  {
    return {mount.component, mount.view};
  }
  std::unordered_map<key_t, std::unique_ptr<slot_t>, key_hash_t> _slots;
  std::vector<std::unique_ptr<slot_t>> _dying;
  std::vector<slot_t *> _touched;
  std::vector<draw_item_t> _items;
  std::vector<prim_t> _prims;
  std::vector<run_t> _runs;
  text_engine_t _text;
  std::vector<prim_t> _glyphs;
  font_t _default_font;
  bool _looked_for_font = false;

  extent_t _logical;
  extent_t _framebuffer;
  float _scale = 1;
  double _input_x = 1;
  double _input_y = 1;

  bool _changed = true;
  waiter_t _change_waiter;
  std::coroutine_handle<> _drained_waiter;

  point_t _pointer;
  bool _has_pointer = false;
  const pressable_t *_hovered = nullptr;
  target_t _held;
};

// ---- the GL stopgap (G23): every primitive is a scissored clear. Corners stay square; borders,
// shadows and text are not drawn. It stays until Vulkan has run on every platform CI covers (G32).
namespace
{
constexpr unsigned gl_color_buffer_bit = 0x4000;
constexpr unsigned gl_scissor_test = 0x0C11;

class gl_renderer_t final : public renderer_t
{
public:
  explicit gl_renderer_t(gl_context_t context)
    : _gl(std::move(context))
  {
  }

  bool load()
  {
    if (!_gl.make_current())
      return false;
    _viewport = _gl.proc<void (*)(int, int, int, int)>("glViewport");
    _scissor = _gl.proc<void (*)(int, int, int, int)>("glScissor");
    _clear_color = _gl.proc<void (*)(float, float, float, float)>("glClearColor");
    _clear = _gl.proc<void (*)(unsigned)>("glClear");
    _enable = _gl.proc<void (*)(unsigned)>("glEnable");
    _disable = _gl.proc<void (*)(unsigned)>("glDisable");
    return _viewport && _scissor && _clear_color && _clear && _enable && _disable;
  }

  [[nodiscard]] std::string describe() const override
  {
    return "gl";
  }

  bool render(const display_list_t &list) override
  {
    if (!_gl.make_current())
      return false;
    const int width = list.framebuffer.width;
    const int height = list.framebuffer.height;
    const double sx = list.logical.width > 0 ? double(width) / list.logical.width : 1.0;
    const double sy = list.logical.height > 0 ? double(height) / list.logical.height : 1.0;
    _viewport(0, 0, width, height);
    _disable(gl_scissor_test);
    _clear_color(list.background.r, list.background.g, list.background.b, list.background.a);
    _clear(gl_color_buffer_bit);
    _enable(gl_scissor_test);
    for (const auto &run : list.runs)
    {
      for (std::uint32_t i = run.first; i < run.first + run.count; ++i)
      {
        const auto &prim = list.prims[i];
        if (prim.blur > 0 || prim.kind != prim_kind_t::shape)
          continue;
        const int x0 = int((run.x + prim.x) * sx + 0.5);
        const int x1 = int((run.x + prim.x + prim.width) * sx + 0.5);
        const int y0 = int((run.y + prim.y) * sy + 0.5);
        const int y1 = int((run.y + prim.y + prim.height) * sy + 0.5);
        _scissor(x0, height - y1, x1 - x0, y1 - y0);
        _clear_color(prim.fill.r, prim.fill.g, prim.fill.b, prim.fill.a);
        _clear(gl_color_buffer_bit);
      }
    }
    _disable(gl_scissor_test);
    return bool(_gl.swap_buffers());
  }

private:
  gl_context_t _gl;
  void (*_viewport)(int, int, int, int) = nullptr;
  void (*_scissor)(int, int, int, int) = nullptr;
  void (*_clear_color)(float, float, float, float) = nullptr;
  void (*_clear)(unsigned) = nullptr;
  void (*_enable)(unsigned) = nullptr;
  void (*_disable)(unsigned) = nullptr;
};
} // namespace

std::unique_ptr<renderer_t> make_gl_renderer(window_t &window, std::string &why)
{
  auto made = gl_context_t::create(window);
  if (!made)
  {
    why = made.error().msg;
    return nullptr;
  }
  auto renderer = std::make_unique<gl_renderer_t>(std::move(*made));
  if (!renderer->load())
  {
    why = "GL entry points missing";
    return nullptr;
  }
  return renderer;
}

namespace
{
std::unique_ptr<renderer_t> choose_renderer(window_t &window, const run_config_t &config)
{
  auto report = [&config](std::string_view what) {
    if (config.on_renderer)
      config.on_renderer(what);
  };
  if (!config.draw)
  {
    report("none: drawing is off");
    return nullptr;
  }
  // A window with nothing native under it (the null backend) can have no surface. Asking anyway
  // would load the Vulkan driver only to fail, which is slow and, under LeakSanitizer, noisy (G18).
  const auto native = window.native();
  if (!native.handle && !native.id)
  {
    report("none: the window has no native surface");
    return nullptr;
  }
  std::string tried;
  if (config.api == render_api_t::automatic || config.api == render_api_t::vulkan)
  {
    std::string why;
    if (auto renderer = make_vulkan_renderer(window, config.vulkan_device, why))
    {
      report(renderer->describe());
      return renderer;
    }
    tried = "vulkan: " + why;
    if (config.api == render_api_t::vulkan)
    {
      report("none: " + tried);
      return nullptr;
    }
  }
  std::string why;
  if (auto renderer = make_gl_renderer(window, why))
  {
    report(renderer->describe() + (tried.empty() ? "" : " (" + tried + ")"));
    return renderer;
  }
  report("none: " + (tried.empty() ? "" : tried + "; ") + "gl: " + why);
  return nullptr;
}

vio::task_t<void> pointer_loop(window_t &window, runtime_t &runtime)
{
  auto events = window.subscribe<pointer_move_event_t, pointer_button_event_t, pointer_enter_event_t>();
  while (auto event = co_await events)
  {
    if (auto *move = std::get_if<pointer_move_event_t>(&*event))
      runtime.pointer_moved(move->position);
    else if (auto *button = std::get_if<pointer_button_event_t>(&*event))
      runtime.button(*button);
    else if (auto *enter = std::get_if<pointer_enter_event_t>(&*event); enter && !enter->entered)
      runtime.pointer_left();
  }
}

// A resize or an expose needs a new frame although no view changed; an expose redraws the display
// list as it stands, since the chunks are clean. The end of this subscription is how the frame loop
// learns the window closed while it was waiting for a change.
vio::task_t<void> repaint_loop(window_t &window, runtime_t &runtime)
{
  auto events = window.subscribe<resize_event_t, expose_event_t>();
  while (co_await events)
    runtime.wake_frame();
  runtime.wake_frame();
}
} // namespace

vio::task_t<void> run_root(window_t &window, mount_t root, run_config_t config)
{
  runtime_t runtime(window, std::move(config));
  runtime.set_root(root);
  auto renderer = choose_renderer(window, runtime.config());
  auto pointer = pointer_loop(window, runtime);
  auto repaints = repaint_loop(window, runtime);
  while (window)
  {
    co_await runtime.changed();
    auto frame = co_await window.frame();
    if (!frame)
      break;
    runtime.step(*frame);
    if (renderer && !renderer->render(runtime.display_list()))
      renderer.reset();
  }
  renderer.reset();
  runtime.shutdown();
  co_await std::move(pointer);
  co_await std::move(repaints);
  co_await runtime.drained();
}

void ready(runtime_t &runtime, waiter_t &waiter) noexcept
{
  runtime.ready(waiter);
}

bool scope_cancelled(const scope_t &scope) noexcept
{
  return scope.cancelled();
}

runtime_t &scope_runtime(scope_t &scope) noexcept
{
  return *scope._runtime;
}

vio::cancellation_t &scope_token(scope_t &scope) noexcept
{
  return scope._token;
}

void scope_woke(scope_t &scope) noexcept
{
  scope.invalidate();
}

void scope_refused(scope_t &scope, std::coroutine_handle<> frame) noexcept
{
  scope.forget(frame);
  scope._runtime->bury(frame);
}

void scope_finished(scope_t &scope, std::coroutine_handle<> frame) noexcept
{
  scope.forget(frame);
  scope._runtime->bury(frame);
}
} // namespace detail

void scope_t::spawn(behaviour_t behaviour)
{
  auto frame = behaviour.release();
  if (!frame)
    return;
  if (_token.is_cancelled())
  {
    frame.destroy();
    return;
  }
  _running.push_back(frame);
  invalidate();
  frame.resume();
}

void scope_t::invalidate() noexcept
{
  if (_slot)
    _runtime->invalidate(*_slot);
}

vio::event_loop_t &scope_t::loop() const noexcept
{
  return _runtime->loop();
}

void scope_t::cancel()
{
  _token.cancel();
}

void scope_t::forget(std::coroutine_handle<> frame) noexcept
{
  std::erase(_running, frame);
}
} // namespace vio::gui::ui
