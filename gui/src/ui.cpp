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

#include <unordered_map>

#include <vio/event_loop.h>

#include "vio/gui/context.h"

namespace vio::gui::ui
{
namespace detail
{
using vio::detail::loop_core_t;
using vio::detail::posted_t;

// What the framework keeps for one mounted component.
struct slot_t
{
  void *component = nullptr;
  node_t (*view)(const void *) = nullptr;
  behaviour_t (*behave)(void *, scope_t &) = nullptr;
  std::unique_ptr<scope_t> scope;
  node_t output;
  bool dirty = true;
  bool reached = false;
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
  void relayout() noexcept
  {
    _layout_dirty = true;
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

  // ---- the frame step
  void step(extent_t size)
  {
    _changed = false;
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

    _items.clear();
    _ordinals.clear();
    place(_root->output, *_root, 0, 0);
    _layout_dirty = false;
    _size = size;
    if (_has_pointer)
      hover(_pointer);
    if (_config.on_layout)
      _config.on_layout(_items);
  }

  void draw(gl_context_t *gl, const frame_t &frame);

  // ---- input
  void pointer_moved(point_t position)
  {
    _pointer = position;
    _has_pointer = true;
    hover(position);
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
    _pointer = event.position;
    _has_pointer = true;
    hover(event.position);
    if (event.pressed)
    {
      _held = target_at(event.position);
      if (_held.source)
        set_flag(_held.source, &pressable_t::_held, true);
      return;
    }
    auto held = std::exchange(_held, {});
    if (held.source)
      set_flag(held.source, &pressable_t::_held, false);
    if (held.empty() || !(target_at(event.position) == held))
      return;
    const auto *item = find(held);
    if (held.source)
      const_cast<pressable_t *>(held.source)->emit(press_event_t{held.source, event.position}, *this);
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

  // Re-run the views that are dirty, starting at `slot`, and mark what is still mounted.
  void build(slot_t &slot)
  {
    slot.reached = true;
    if (slot.dirty)
    {
      slot.dirty = false;
      slot.output = slot.view(slot.component);
    }
    visit_mounts(slot.output);
  }

  void visit_mounts(const node_t &node)
  {
    if (const auto *mount = std::get_if<mount_t>(&node))
    {
      auto *child = slot_for(*mount);
      if (!child->reached)
        build(*child);
      return;
    }
    const std::vector<node_t> *children = nullptr;
    if (const auto *row = std::get_if<row_t>(&node))
      children = &row->children;
    else if (const auto *column = std::get_if<column_t>(&node))
      children = &column->children;
    if (children)
    {
      for (const auto &child : *children)
        visit_mounts(child);
    }
  }

  extent_t measure(const node_t &node)
  {
    if (const auto *box = std::get_if<box_t>(&node))
      return box->size;
    if (const auto *mount = std::get_if<mount_t>(&node))
    {
      auto *child = existing(*mount);
      return child ? measure(child->output) : extent_t{};
    }
    const bool horizontal = std::holds_alternative<row_t>(node);
    const auto &children = horizontal ? std::get<row_t>(node).children : std::get<column_t>(node).children;
    const int gap = horizontal ? std::get<row_t>(node).gap : std::get<column_t>(node).gap;
    extent_t total;
    for (std::size_t i = 0; i < children.size(); ++i)
    {
      const auto size = measure(children[i]);
      const int spacing = i > 0 ? gap : 0;
      if (horizontal)
      {
        total.width += size.width + spacing;
        total.height = std::max(total.height, size.height);
      }
      else
      {
        total.height += size.height + spacing;
        total.width = std::max(total.width, size.width);
      }
    }
    return total;
  }

  void place(const node_t &node, slot_t &slot, int x, int y)
  {
    if (const auto *box = std::get_if<box_t>(&node))
    {
      const int ordinal = _ordinals[&slot]++;
      _items.push_back(draw_item_t{{x, y, box->size.width, box->size.height}, box->color, box, &slot, ordinal});
      return;
    }
    if (const auto *mount = std::get_if<mount_t>(&node))
    {
      if (auto *child = existing(*mount))
        place(child->output, *child, x, y);
      return;
    }
    const bool horizontal = std::holds_alternative<row_t>(node);
    const auto &children = horizontal ? std::get<row_t>(node).children : std::get<column_t>(node).children;
    const int gap = horizontal ? std::get<row_t>(node).gap : std::get<column_t>(node).gap;
    for (const auto &child : children)
    {
      place(child, slot, x, y);
      const auto size = measure(child);
      if (horizontal)
        x += size.width + gap;
      else
        y += size.height + gap;
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
  std::vector<draw_item_t> _items;
  std::unordered_map<slot_t *, int> _ordinals;
  extent_t _size;

  bool _changed = true;
  bool _layout_dirty = true;
  waiter_t _change_waiter;
  std::coroutine_handle<> _drained_waiter;

  struct gl_procs_t
  {
    void (*viewport)(int, int, int, int) = nullptr;
    void (*scissor)(int, int, int, int) = nullptr;
    void (*clear_color)(float, float, float, float) = nullptr;
    void (*clear)(unsigned) = nullptr;
    void (*enable)(unsigned) = nullptr;
    void (*disable)(unsigned) = nullptr;
  } _gl;

  point_t _pointer;
  bool _has_pointer = false;
  const pressable_t *_hovered = nullptr;
  target_t _held;
};

namespace
{
constexpr unsigned gl_color_buffer_bit = 0x4000;
constexpr unsigned gl_scissor_test = 0x0C11;
} // namespace

// Every box is a scissored clear: no shaders, no buffers, nothing linked.
void runtime_t::draw(gl_context_t *gl, const frame_t &frame)
{
  if (!gl->make_current())
    return;
  if (!_gl.clear)
  {
    _gl.viewport = gl->proc<void (*)(int, int, int, int)>("glViewport");
    _gl.scissor = gl->proc<void (*)(int, int, int, int)>("glScissor");
    _gl.clear_color = gl->proc<void (*)(float, float, float, float)>("glClearColor");
    _gl.clear = gl->proc<void (*)(unsigned)>("glClear");
    _gl.enable = gl->proc<void (*)(unsigned)>("glEnable");
    _gl.disable = gl->proc<void (*)(unsigned)>("glDisable");
    if (!_gl.viewport || !_gl.scissor || !_gl.clear_color || !_gl.clear || !_gl.enable || !_gl.disable)
    {
      _gl = {};
      return;
    }
  }
  const int width = frame.framebuffer.width;
  const int height = frame.framebuffer.height;
  const double sx = frame.size.width > 0 ? double(width) / frame.size.width : 1.0;
  const double sy = frame.size.height > 0 ? double(height) / frame.size.height : 1.0;
  _gl.viewport(0, 0, width, height);
  _gl.disable(gl_scissor_test);
  const auto &background = _config.background;
  _gl.clear_color(background.r, background.g, background.b, background.a);
  _gl.clear(gl_color_buffer_bit);
  _gl.enable(gl_scissor_test);
  for (const auto &item : _items)
  {
    const int x0 = int(item.rect.x * sx + 0.5);
    const int x1 = int((item.rect.x + item.rect.width) * sx + 0.5);
    const int y0 = int(item.rect.y * sy + 0.5);
    const int y1 = int((item.rect.y + item.rect.height) * sy + 0.5);
    _gl.scissor(x0, height - y1, x1 - x0, y1 - y0);
    _gl.clear_color(item.color.r, item.color.g, item.color.b, item.color.a);
    _gl.clear(gl_color_buffer_bit);
  }
  _gl.disable(gl_scissor_test);
  (void)gl->swap_buffers();
}

namespace
{
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

// A resize needs a new frame even when no view changed, and the end of this subscription is how the
// frame loop learns the window closed while it was waiting for a change.
vio::task_t<void> resize_loop(window_t &window, runtime_t &runtime)
{
  auto resizes = window.subscribe<resize_event_t>();
  while (co_await resizes)
    runtime.relayout();
  runtime.wake_frame();
}
} // namespace

vio::task_t<void> run_root(window_t &window, mount_t root, run_config_t config)
{
  const bool draw = config.draw;
  runtime_t runtime(window, std::move(config));
  runtime.set_root(root);
  std::optional<gl_context_t> gl;
  if (draw)
  {
    if (auto made = gl_context_t::create(window))
      gl.emplace(std::move(*made));
  }
  auto pointer = pointer_loop(window, runtime);
  auto resizes = resize_loop(window, runtime);
  while (window)
  {
    co_await runtime.changed();
    auto frame = co_await window.frame();
    if (!frame)
      break;
    runtime.step(frame->size);
    if (gl)
      runtime.draw(&*gl, *frame);
  }
  gl.reset();
  runtime.shutdown();
  co_await std::move(pointer);
  co_await std::move(resizes);
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
