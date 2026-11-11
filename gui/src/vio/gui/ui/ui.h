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

#pragma once

// A declarative toolkit on the window layer. A component is one struct: its state, a const view()
// that describes it as a tree of struct literals, and optionally a behave(scope_t &) coroutine that
// reacts to events for as long as the component is mounted. gui/PLAN.md, "UI toolkit", is the
// design; this header is phase 6 of it.

#include <algorithm>
#include <cassert>
#include <concepts>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include <vio/cancellation.h>
#include <vio/task.h>

#include "vio/gui/gui.h"

namespace vio::gui::ui
{
class scope_t;
class pressable_t;
class behaviour_t;

namespace detail
{
class runtime_t;
struct slot_t;
struct font_data_t;
using gui::detail::value_waiter_t;
using gui::detail::waiter_list_t;
using gui::detail::waiter_t;
} // namespace detail

struct color_t
{
  float r = 0;
  float g = 0;
  float b = 0;
  float a = 1;
  friend bool operator==(const color_t &, const color_t &) = default;
};

struct rect_t
{
  int x = 0;
  int y = 0;
  int width = 0;
  int height = 0;
  friend bool operator==(const rect_t &, const rect_t &) = default;

  [[nodiscard]] bool contains(point_t p) const noexcept
  {
    return p.x >= x && p.y >= y && p.x < x + width && p.y < y + height;
  }
};

// A point in logical units, for geometry a node carries: a polyline's points.
struct vec2_t
{
  float x = 0;
  float y = 0;
  friend bool operator==(const vec2_t &, const vec2_t &) = default;
};

// Space inside a container's edge, in logical units. `.padding = 8` is all four sides, `{12, 6}`
// horizontal then vertical, `{l, t, r, b}` each.
struct edges_t
{
  int left = 0;
  int top = 0;
  int right = 0;
  int bottom = 0;

  constexpr edges_t() = default;
  constexpr edges_t(int all) noexcept // NOLINT(google-explicit-constructor)
    : left(all)
    , top(all)
    , right(all)
    , bottom(all)
  {
  }
  constexpr edges_t(int horizontal, int vertical) noexcept
    : left(horizontal)
    , top(vertical)
    , right(horizontal)
    , bottom(vertical)
  {
  }
  constexpr edges_t(int left_, int top_, int right_, int bottom_) noexcept
    : left(left_)
    , top(top_)
    , right(right_)
    , bottom(bottom_)
  {
  }
  friend bool operator==(const edges_t &, const edges_t &) = default;
};

// Where a child sits across the space it was given. `baseline` lines up the first baseline of each
// child of a row -- text's, or the first text inside a container -- and a child with none sits on
// it by its bottom edge. Anywhere else baseline means start. `stretch` gives each child the whole
// breadth: a box grows to it, a row or column lays its own children out in it.
enum class align_t : std::uint8_t
{
  start,
  center,
  end,
  baseline,
  stretch,
};

// ---------------------------------------------------------------------------------------------
// Event sources

// A left button pressed and released on the same box. `source` is the pressable it was pressed on,
// so one subscription over several sources can tell them apart: `press->source == &inc`.
struct press_event_t
{
  const pressable_t *source = nullptr;
  point_t position;
};

namespace detail
{
template <typename E>
class source_t;

// One subscriber's queue over one or more sources. It is the only place events are kept, and like a
// window subscription it sees every event that arrives after it was made.
template <typename E>
class subscription_core_t
{
public:
  subscription_core_t() = default;
  subscription_core_t(const subscription_core_t &) = delete;
  subscription_core_t &operator=(const subscription_core_t &) = delete;
  inline ~subscription_core_t();

  inline void push(const E &event, runtime_t &runtime);
  inline void source_gone(source_t<E> *source) noexcept;

  std::vector<source_t<E> *> sources;
  std::deque<E> queue;
  waiter_list_t waiters;
};

template <typename E>
class source_t
{
public:
  source_t() = default;
  // A source is identity, and identity cannot be copied. Moving one is allowed only while nothing
  // subscribes to it -- a component is moved into ui::run before any behaviour has started -- and
  // the result is a fresh source.
  source_t(const source_t &) = delete;
  source_t &operator=(const source_t &) = delete;
  source_t(source_t &&other) noexcept
  {
    assert(other._subscribers.empty() && "a source cannot be moved while something subscribes to it");
    (void)other;
  }
  source_t &operator=(source_t &&other) noexcept
  {
    assert(_subscribers.empty() && other._subscribers.empty() && "a source cannot be moved while something subscribes to it");
    (void)other;
    return *this;
  }
  ~source_t()
  {
    for (auto *subscriber : _subscribers)
      subscriber->source_gone(this);
  }

  void emit(const E &event, runtime_t &runtime)
  {
    for (std::size_t i = 0; i < _subscribers.size(); ++i)
      _subscribers[i]->push(event, runtime);
  }

  void add(subscription_core_t<E> *subscriber)
  {
    _subscribers.push_back(subscriber);
  }
  void remove(subscription_core_t<E> *subscriber) noexcept
  {
    std::erase(_subscribers, subscriber);
  }

private:
  std::vector<subscription_core_t<E> *> _subscribers;
};

// What runtime_t does for a header template. Defined in ui.cpp.
void ready(runtime_t &runtime, waiter_t &waiter) noexcept;

template <typename E>
subscription_core_t<E>::~subscription_core_t()
{
  for (auto *source : sources)
    source->remove(this);
}

template <typename E>
void subscription_core_t<E>::push(const E &event, runtime_t &runtime)
{
  if (auto *front = waiters.pop_front())
  {
    static_cast<value_waiter_t<E> *>(front)->value.emplace(event);
    ready(runtime, *front);
    return;
  }
  queue.push_back(event);
}

template <typename E>
void subscription_core_t<E>::source_gone(source_t<E> *source) noexcept
{
  std::erase(sources, source);
}

// The awaitable of one subscription. A parked await is woken with std::nullopt when the scope of the
// behaviour awaiting it is cancelled; cancel_wait is how the behaviour's await wrapper does that.
template <typename E>
class subscription_awaitable_t : value_waiter_t<E>
{
public:
  explicit subscription_awaitable_t(subscription_core_t<E> *core) noexcept
    : _core(core)
  {
  }
  subscription_awaitable_t(const subscription_awaitable_t &) = delete;
  subscription_awaitable_t &operator=(const subscription_awaitable_t &) = delete;
  ~subscription_awaitable_t()
  {
    if (this->list)
      this->list->remove(*this);
  }

  [[nodiscard]] bool await_ready() noexcept
  {
    if (!_core)
      return true;
    if (_core->waiters.empty() && !_core->queue.empty())
    {
      this->value.emplace(std::move(_core->queue.front()));
      _core->queue.pop_front();
      return true;
    }
    return false;
  }
  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    this->handle = continuation;
    _core->waiters.push_back(*this);
  }
  std::optional<E> await_resume() noexcept
  {
    return std::move(this->value);
  }

  void cancel_wait(runtime_t &runtime) noexcept
  {
    if (this->list != &_core->waiters)
      return;
    _core->waiters.remove(*this);
    ready(runtime, *this);
  }

private:
  subscription_core_t<E> *_core;
};
} // namespace detail

// Something that can be pressed. It is a member of a component and its identity is its address, so
// the box that shows it may be rebuilt freely. It also carries what the pointer is doing to it, for a
// view to draw.
class pressable_t : public detail::source_t<press_event_t>
{
public:
  pressable_t() = default;
  pressable_t(pressable_t &&other) noexcept
    : source_t(std::move(other))
  {
  }
  pressable_t &operator=(pressable_t &&other) noexcept
  {
    source_t::operator=(std::move(other));
    return *this;
  }

  // The pointer is over it.
  [[nodiscard]] bool hovered() const noexcept
  {
    return _hovered;
  }
  // The left button went down on it and has not been released yet. Stays true while the pointer is
  // dragged off, which is what lets a press be abandoned by releasing elsewhere.
  [[nodiscard]] bool held() const noexcept
  {
    return _held;
  }

private:
  friend class detail::runtime_t;
  bool _hovered = false;
  bool _held = false;
};

// `while (auto event = co_await presses)` -- yields std::nullopt once the awaiting behaviour's scope
// is cancelled. One coroutine at a time should await a given subscription.
template <typename E>
class subscription_t
{
public:
  subscription_t() = default;
  explicit subscription_t(std::unique_ptr<detail::subscription_core_t<E>> core) noexcept
    : _core(std::move(core))
  {
  }
  subscription_t(subscription_t &&) noexcept = default;
  subscription_t &operator=(subscription_t &&) noexcept = default;

  [[nodiscard]] detail::subscription_awaitable_t<E> operator co_await() noexcept
  {
    return detail::subscription_awaitable_t<E>(_core.get());
  }

private:
  std::unique_ptr<detail::subscription_core_t<E>> _core;
};

template <typename E, typename... Sources>
  requires(sizeof...(Sources) > 0 && (std::derived_from<Sources, detail::source_t<E>> && ...))
[[nodiscard]] subscription_t<E> subscribe(Sources &...sources)
{
  auto core = std::make_unique<detail::subscription_core_t<E>>();
  (
    [&](detail::source_t<E> &source) {
      source.add(core.get());
      core->sources.push_back(&source);
    }(sources),
    ...);
  return subscription_t<E>(std::move(core));
}

// ---------------------------------------------------------------------------------------------
// Nodes

// What a box reports to. Constructible from a pressable, so a literal reads `.events = inc`.
struct event_ref_t
{
  const pressable_t *source = nullptr;

  event_ref_t() = default;
  event_ref_t(const pressable_t &pressable) noexcept // NOLINT(google-explicit-constructor)
    : source(&pressable)
  {
  }
};

struct node_t;

// A soft shadow under a box: the box's shape, moved by the offset and blurred. `blur` is the
// Gaussian's standard deviation in logical units; a shadow with a transparent color is not drawn.
struct shadow_t
{
  float x = 0;
  float y = 0;
  float blur = 0;
  color_t color = {0, 0, 0, 0};
};

struct box_t
{
  extent_t size;
  // Colors are sRGB, as authored; the renderer blends in linear space (G27).
  color_t color;
  float radius = 0;
  float border_width = 0;
  color_t border_color = {0, 0, 0, 0};
  shadow_t shadow;
  event_ref_t events;
  // A one-line handler. It runs when the box is pressed, and its component is rebuilt after it.
  // For anything that spans several events, subscribe in behave() instead.
  std::function<void()> on_press;
  // In a row or column, its share of the space left along it: what remains after every child has
  // its natural size is split between the children in proportion to `grow` (G42).
  float grow = 0;
  // Children are drawn on the box, each placed inside the padding by the two alignments; they
  // overlap, so a box holding several usually holds one row or column. With children, `size` is a
  // minimum: the box grows to fit them and its padding.
  edges_t padding;
  align_t align_x = align_t::center;
  align_t align_y = align_t::center;
  std::vector<node_t> children;
};

// ---------------------------------------------------------------------------------------------
// Text and icons (gui/PLAN.md, "Rendering"; G27, G39)

// A loaded font: a TrueType or OpenType file, or the first face of a collection. Cheap to copy and
// safe to share between threads; what is not (FreeType faces, the atlas) is kept per window.
class font_t
{
public:
  font_t() = default;

  static std::expected<font_t, std::string> from_file(const std::string &path);
  static std::expected<font_t, std::string> from_memory(std::vector<std::byte> bytes);
  // The platform's UI font, found at a known path: Segoe UI on Windows, the system font on macOS,
  // DejaVu Sans, Noto Sans or Liberation Sans on Linux. No fontconfig lookup (G40).
  static std::expected<font_t, std::string> system_default();

  explicit operator bool() const noexcept
  {
    return bool(_data);
  }
  [[nodiscard]] const detail::font_data_t *data() const noexcept
  {
    return _data.get();
  }
  friend bool operator==(const font_t &, const font_t &) = default;

private:
  explicit font_t(std::shared_ptr<const detail::font_data_t> data) noexcept
    : _data(std::move(data))
  {
  }
  std::shared_ptr<const detail::font_data_t> _data;
};

// One line of text, shaped as a single run: HarfBuzz picks the direction and script from the text
// itself, so a line of Arabic or Devanagari is right, but a line mixing directions is not (G40).
// `size` is the font size in logical units.
struct text_t
{
  std::string text;
  float size = 14;
  color_t color = {1, 1, 1, 1};
  // Empty: run_config_t::font, else font_t::system_default().
  font_t font;
  // Measure by the ink rather than the line: the size is the bounds of the glyphs as drawn, not the
  // font's ascent and descent, so a symbol centred on a button is centred by what is seen. A "+"
  // sits on the maths axis, well below the middle of its line, and looks low without this. The
  // baseline moves with the top.
  bool tight = false;
};

// A vector shape for an icon, in a unit square with (0, 0) at the top left. Contours close
// themselves. Filled non-zero unless `even_odd`.
class path_t
{
public:
  path_t &move_to(float x, float y);
  path_t &line_to(float x, float y);
  path_t &quad_to(float cx, float cy, float x, float y);
  path_t &cubic_to(float c1x, float c1y, float c2x, float c2y, float x, float y);
  path_t &close();

  bool even_odd = false;

  enum class tag_t : std::uint8_t
  {
    on,
    quad_control,
    cubic_control,
  };
  struct point_t
  {
    float x = 0;
    float y = 0;
    tag_t tag = tag_t::on;
  };
  [[nodiscard]] std::span<const point_t> points() const noexcept
  {
    return _points;
  }
  // The index one past each contour's last point.
  [[nodiscard]] std::span<const std::size_t> ends() const noexcept
  {
    return _ends;
  }

private:
  std::vector<point_t> _points;
  std::vector<std::size_t> _ends;
};

// A path drawn `size` logical units square, rasterized into the glyph atlas like a glyph. The
// pointer is the cache key: share one path_t between every icon showing it.
struct icon_t
{
  std::shared_ptr<const path_t> path;
  float size = 16;
  color_t color = {1, 1, 1, 1};
};

// Children side by side, left to right. `align` places each across the row's height.
struct row_t
{
  int gap = 0;
  align_t align = align_t::start;
  edges_t padding;
  // As box_t::grow, inside a row or column of its own.
  float grow = 0;
  std::vector<node_t> children;
};

// Children top to bottom. `align` places each across the column's width.
struct column_t
{
  int gap = 0;
  align_t align = align_t::start;
  edges_t padding;
  float grow = 0;
  std::vector<node_t> children;
};

// Empty space that grows: `row_t{.children = {label, ui::spacer_t{}, button}}` puts the button at
// the far end of a row that was given more room than it needs.
struct spacer_t
{
  float grow = 1;
  extent_t size;
};

// Children at an offset from where this node is placed, overlapping. The offset may be fractional:
// what is drawn moves smoothly, which is what a scrolling plot needs; hit testing rounds. Its size
// reaches from its own origin to the far edge of its farthest child.
struct at_t
{
  float x = 0;
  float y = 0;
  std::vector<node_t> children;
};

// A line through `points`, in logical units from the top left of `size`, which is the room it
// takes in layout. Joins and ends are round. Drawn on the GPU per segment (G41): a translucent line
// darkens where segments meet, so draw lines opaque.
struct polyline_t
{
  extent_t size;
  std::vector<vec2_t> points;
  // Line width in logical units; 0 draws no line.
  float width = 1.5f;
  color_t color = {1, 1, 1, 1};
  // With alpha above 0, the area between the line and the bottom of `size` is filled. Where x
  // runs backwards between two points that stretch is not filled.
  color_t fill = {0, 0, 0, 0};
  // With a diameter above 0, a round marker in `color` at every point: a scatter plot when
  // `width` is 0.
  float marker = 0;
};

// A child component in its parent's output. It refers to the child; it does not hold its nodes, so
// rebuilding the parent does not rebuild the child.
struct mount_t
{
  void *component = nullptr;
  node_t (*view)(const void *component) = nullptr;
  behaviour_t (*behave)(void *component, scope_t &scope) = nullptr;
  // Shares ownership of a list_t item, so an erased item lives until its behaviours have ended.
  std::shared_ptr<void> keep;
  // Props (ui::mount(child, props)): compared with the child's own each frame and, when unequal,
  // copied into it, which rebuilds it.
  std::shared_ptr<const void> props;
  bool (*props_equal)(const void *component, const void *props) = nullptr;
  void (*apply_props)(void *component, const void *props) = nullptr;
};

struct node_t : std::variant<box_t, row_t, column_t, mount_t, text_t, icon_t, at_t, polyline_t, spacer_t>
{
  using variant::variant;
};

// ---------------------------------------------------------------------------------------------
// Behaviours

namespace detail
{
template <typename A>
decltype(auto) get_awaiter(A &&awaitable)
{
  if constexpr (requires { std::forward<A>(awaitable).operator co_await(); })
    return std::forward<A>(awaitable).operator co_await();
  else if constexpr (requires { operator co_await(std::forward<A>(awaitable)); })
    return operator co_await(std::forward<A>(awaitable));
  else
    return std::forward<A>(awaitable);
}

template <typename T>
concept ui_cancellable = requires(T &awaiter, runtime_t &runtime) { awaiter.cancel_wait(runtime); };

// An await a cancelled scope does not refuse: joining a child scope.
template <typename T>
concept ui_uninterruptible = requires { requires std::remove_cvref_t<T>::uninterruptible; };

// Implemented in ui.cpp, so the templates below need only declarations.
[[nodiscard]] bool scope_cancelled(const scope_t &scope) noexcept;
[[nodiscard]] runtime_t &scope_runtime(scope_t &scope) noexcept;
[[nodiscard]] vio::cancellation_t &scope_token(scope_t &scope) noexcept;
void scope_woke(scope_t &scope) noexcept;
void scope_refused(scope_t &scope, std::coroutine_handle<> frame) noexcept;
void scope_finished(scope_t &scope, std::coroutine_handle<> frame) noexcept;

// Every co_await in a behaviour goes through this. Resuming marks the component dirty -- a
// behaviour that woke up rebuilds its view. A cancelled scope is refused at the suspension point:
// the operation is never armed, nothing else holds the frame, and the scope destroys it later.
// An awaitable the toolkit owns (a subscription) is also woken by cancellation, with nothing.
template <typename Awaiter>
class guarded_t
{
public:
  template <typename A>
  guarded_t(A &&awaitable, scope_t &scope)
    : _inner(get_awaiter(std::forward<A>(awaitable)))
    , _scope(&scope)
  {
  }

  bool await_ready()
  {
    if (!ui_uninterruptible<Awaiter> && scope_cancelled(*_scope))
      return false;
    return _inner.await_ready();
  }

  template <typename Promise>
  std::coroutine_handle<> await_suspend(std::coroutine_handle<Promise> frame)
  {
    if (!ui_uninterruptible<Awaiter> && scope_cancelled(*_scope))
    {
      scope_refused(*_scope, frame);
      return std::noop_coroutine();
    }
    if constexpr (ui_cancellable<std::remove_reference_t<Awaiter>>)
    {
      auto *inner = &_inner;
      auto *runtime = &scope_runtime(*_scope);
      _cancel = scope_token(*_scope).register_callback([inner, runtime] { inner->cancel_wait(*runtime); });
    }
    // Nothing of this object may be touched after the inner await_suspend: an operation that
    // completes inside it can resume the frame, run it on, and end this await.
    using result_t = decltype(_inner.await_suspend(frame));
    if constexpr (std::is_void_v<result_t>)
    {
      _inner.await_suspend(frame);
      return std::noop_coroutine();
    }
    else if constexpr (std::is_same_v<result_t, bool>)
    {
      if (_inner.await_suspend(frame))
        return std::noop_coroutine();
      return frame;
    }
    else
      return _inner.await_suspend(frame);
  }

  decltype(auto) await_resume()
  {
    _cancel.reset();
    scope_woke(*_scope);
    return _inner.await_resume();
  }

private:
  Awaiter _inner;
  scope_t *_scope;
  vio::registration_t _cancel;
};

template <typename A>
guarded_t(A &&, scope_t &) -> guarded_t<decltype(get_awaiter(std::declval<A>()))>;
} // namespace detail

namespace detail
{
// What every coroutine run in a scope shares: it is lazy, finds its scope among its parameters --
// the first, or the second after a member function's object -- so one without a scope_t &
// parameter does not compile, goes through guarded_t at every co_await, and hands its frame back
// to the scope when it ends.
struct promise_base_t
{
  template <typename... Rest>
  explicit promise_base_t(scope_t &scope, Rest &...) noexcept
    : scope(&scope)
  {
  }
  template <typename Self, typename... Rest>
    requires(!std::same_as<std::remove_cvref_t<Self>, scope_t>)
  promise_base_t(Self &, scope_t &scope, Rest &...) noexcept
    : scope(&scope)
  {
  }

  std::suspend_always initial_suspend() noexcept
  {
    return {};
  }
  struct final_t
  {
    [[nodiscard]] bool await_ready() const noexcept
    {
      return false;
    }
    template <typename Promise>
    void await_suspend(std::coroutine_handle<Promise> frame) noexcept
    {
      scope_finished(*frame.promise().scope, frame);
    }
    void await_resume() const noexcept
    {
    }
  };
  final_t final_suspend() noexcept
  {
    return {};
  }
  void unhandled_exception() noexcept
  {
    std::terminate();
  }

  template <typename A>
  auto await_transform(A &&awaitable)
  {
    return guarded_t(std::forward<A>(awaitable), *scope);
  }

  scope_t *scope;
};

// Where a job's result waits for whoever awaits it. Outside the frame, because the scope destroys
// the frame in the beat after it ends; finished when the frame is destroyed, with a value if the
// job returned one and without if its scope was cancelled first.
template <typename T>
struct job_state_t
{
  std::optional<T> value;
  bool done = false;
  runtime_t *runtime = nullptr;
  waiter_t *waiter = nullptr;

  void finish() noexcept
  {
    done = true;
    if (auto *w = std::exchange(waiter, nullptr))
      ready(*runtime, *w);
  }
};
} // namespace detail

// The coroutine type of behave() and of everything spawned into a scope. Unlike task_t it is lazy:
// scope_t::spawn starts it.
class behaviour_t
{
public:
  struct promise_type : detail::promise_base_t
  {
    using promise_base_t::promise_base_t;

    behaviour_t get_return_object() noexcept
    {
      return behaviour_t(std::coroutine_handle<promise_type>::from_promise(*this));
    }
    void return_void() noexcept
    {
    }
  };

  behaviour_t(behaviour_t &&other) noexcept
    : _frame(std::exchange(other._frame, {}))
  {
  }
  behaviour_t &operator=(behaviour_t &&other) noexcept
  {
    if (this != &other)
    {
      if (_frame)
        _frame.destroy();
      _frame = std::exchange(other._frame, {});
    }
    return *this;
  }
  behaviour_t(const behaviour_t &) = delete;
  behaviour_t &operator=(const behaviour_t &) = delete;
  // A behaviour never spawned is still at its initial suspension, so destroying it is safe.
  ~behaviour_t()
  {
    if (_frame)
      _frame.destroy();
  }

  [[nodiscard]] std::coroutine_handle<promise_type> release() noexcept
  {
    return std::exchange(_frame, {});
  }

private:
  explicit behaviour_t(std::coroutine_handle<promise_type> frame) noexcept
    : _frame(frame)
  {
  }
  std::coroutine_handle<promise_type> _frame;
};

template <typename T>
class spawned_t;

// A behaviour with a result: `ui::job_t<int> fetch(ui::scope_t &scope)`. Spawned like any other,
// it gives back a spawned_t<T> to await the result with.
template <typename T>
class job_t
{
public:
  struct promise_type : detail::promise_base_t
  {
    using promise_base_t::promise_base_t;
    promise_type(const promise_type &) = delete;
    promise_type &operator=(const promise_type &) = delete;
    ~promise_type()
    {
      state->finish();
    }

    job_t get_return_object()
    {
      state->runtime = &detail::scope_runtime(*scope);
      return job_t(std::coroutine_handle<promise_type>::from_promise(*this));
    }
    template <typename V>
    void return_value(V &&value)
    {
      state->value.emplace(std::forward<V>(value));
    }

    std::shared_ptr<detail::job_state_t<T>> state = std::make_shared<detail::job_state_t<T>>();
  };

  job_t(job_t &&other) noexcept
    : _frame(std::exchange(other._frame, {}))
  {
  }
  job_t(const job_t &) = delete;
  job_t &operator=(const job_t &) = delete;
  job_t &operator=(job_t &&) = delete;
  ~job_t()
  {
    if (_frame)
      _frame.destroy();
  }

  [[nodiscard]] std::coroutine_handle<promise_type> release() noexcept
  {
    return std::exchange(_frame, {});
  }

private:
  explicit job_t(std::coroutine_handle<promise_type> frame) noexcept
    : _frame(frame)
  {
  }
  std::coroutine_handle<promise_type> _frame;
};

// A spawned job's result: `if (auto value = co_await spawned)`. std::nullopt when the job's scope
// was cancelled before it returned. Dropping it does not stop the job, which belongs to its scope.
template <typename T>
class spawned_t
{
public:
  explicit spawned_t(std::shared_ptr<detail::job_state_t<T>> state) noexcept
    : _state(std::move(state))
  {
  }

  [[nodiscard]] bool done() const noexcept
  {
    return _state->done;
  }

  struct awaitable_t : detail::waiter_t
  {
    // Not refused by a cancelled scope: the job is cancelled whenever the awaiting scope is, so
    // the wait is bounded, and refusing it could end a child scope's owner before the job.
    static constexpr bool uninterruptible = true;
    std::shared_ptr<detail::job_state_t<T>> state;
    awaitable_t(std::shared_ptr<detail::job_state_t<T>> s) noexcept
      : state(std::move(s))
    {
    }
    awaitable_t(const awaitable_t &) = delete;
    awaitable_t &operator=(const awaitable_t &) = delete;
    ~awaitable_t()
    {
      if (state->waiter == this)
        state->waiter = nullptr;
    }
    [[nodiscard]] bool await_ready() const noexcept
    {
      return state->done;
    }
    void await_suspend(std::coroutine_handle<> continuation) noexcept
    {
      handle = continuation;
      state->waiter = this;
    }
    std::optional<T> await_resume() noexcept
    {
      return std::move(state->value);
    }
  };
  [[nodiscard]] awaitable_t operator co_await() const noexcept
  {
    return awaitable_t(_state);
  }

private:
  std::shared_ptr<detail::job_state_t<T>> _state;
};

// The lifetime of a mounted component. Every behaviour of the component runs in it: behave() first,
// then whatever is spawned. Unmounting cancels it; the component's storage is released only once no
// behaviour is left running, since every one of them holds `this`.
class scope_t
{
public:
  scope_t(detail::runtime_t &runtime, detail::slot_t *slot) noexcept
    : _runtime(&runtime)
    , _slot(slot)
  {
  }
  // A child scope, for work shorter than the component's life. It is cancelled with its parent or
  // on its own with cancel(), and `co_await join()` resolves once nothing in it runs -- which its
  // owner must await before the scope goes out of scope, since what runs in it holds it.
  explicit scope_t(scope_t &parent);
  scope_t(const scope_t &) = delete;
  scope_t &operator=(const scope_t &) = delete;
  ~scope_t()
  {
    assert(_running.empty() && "a scope was destroyed with behaviours still running: co_await join() first");
  }

  // Start a behaviour in this scope. It runs to its first suspension before spawn returns, and it
  // belongs to the scope, not to whoever spawned it.
  void spawn(behaviour_t behaviour);
  template <typename T>
  spawned_t<T> spawn(job_t<T> job)
  {
    auto frame = job.release();
    auto state = frame.promise().state;
    start(frame);
    return spawned_t<T>(std::move(state));
  }

  // End everything running in this scope: operations started with its token resolve as cancelled,
  // and each behaviour stops at its next co_await.
  void cancel();

  class join_awaitable_t : detail::waiter_t
  {
  public:
    // Exempt from the refusal a cancelled scope gives every other await: the owner of a child scope
    // must outlive what runs in it, cancelled or not.
    static constexpr bool uninterruptible = true;

    explicit join_awaitable_t(scope_t &scope) noexcept
      : _scope(&scope)
    {
    }
    [[nodiscard]] bool await_ready() const noexcept
    {
      return _scope->_running.empty();
    }
    void await_suspend(std::coroutine_handle<> continuation) noexcept
    {
      handle = continuation;
      _scope->_joiner = this;
    }
    void await_resume() const noexcept
    {
    }

  private:
    scope_t *_scope;
  };
  [[nodiscard]] join_awaitable_t join() noexcept
  {
    return join_awaitable_t(*this);
  }

  // Rebuild this component's view at the next frame. Resuming a behaviour already does this; call
  // it for a change made where no behaviour woke up.
  void invalidate() noexcept;

  [[nodiscard]] vio::event_loop_t &loop() const noexcept;
  // The window the component is shown in, for what the toolkit does not wrap: keys, text.
  [[nodiscard]] gui::window_t &window() const noexcept;

  // Pass to operations a behaviour starts, so unmounting resolves them as cancelled.
  [[nodiscard]] vio::cancellation_t *token() noexcept
  {
    return &_token;
  }
  [[nodiscard]] bool cancelled() const noexcept
  {
    return _token.is_cancelled();
  }

  // For a reader, which takes no token: cancel it when this scope is cancelled. Keep the returned
  // registration for as long as the reader is awaited.
  template <typename Reader>
  [[nodiscard]] vio::registration_t bind(Reader &reader)
  {
    if (_token.is_cancelled())
    {
      reader.cancel();
      return {};
    }
    return _token.register_callback([&reader] { reader.cancel(); });
  }

  [[nodiscard]] std::size_t running() const noexcept
  {
    return _running.size();
  }

private:
  friend class detail::runtime_t;
  friend bool detail::scope_cancelled(const scope_t &) noexcept;
  friend detail::runtime_t &detail::scope_runtime(scope_t &) noexcept;
  friend vio::cancellation_t &detail::scope_token(scope_t &) noexcept;
  friend void detail::scope_woke(scope_t &) noexcept;
  friend void detail::scope_refused(scope_t &, std::coroutine_handle<>) noexcept;
  friend void detail::scope_finished(scope_t &, std::coroutine_handle<>) noexcept;

  void start(std::coroutine_handle<> frame);
  void forget(std::coroutine_handle<> frame) noexcept;

  detail::runtime_t *_runtime;
  detail::slot_t *_slot;
  vio::cancellation_t _token;
  vio::registration_t _on_parent;
  detail::waiter_t *_joiner = nullptr;
  std::vector<std::coroutine_handle<>> _running;
};

// ---------------------------------------------------------------------------------------------
// Components

template <typename C>
concept component = requires(const C &c) {
  { c.view() } -> std::convertible_to<node_t>;
};

template <typename C>
concept has_behaviour = requires(C &c, scope_t &scope) {
  { c.behave(scope) } -> std::same_as<behaviour_t>;
};

// A child component in a view. The child must be a member of the component whose view mounts it,
// or otherwise outlive it: identity is its address. A view is const, but mounting starts the
// child's behaviour, which is why the reference is taken as const and used as mutable -- the
// component itself is never const, only the view's access to it.
template <component C>
[[nodiscard]] mount_t mount(const C &child) noexcept
{
  mount_t node;
  node.component = const_cast<C *>(&child);
  node.view = [](const void *component) -> node_t { return static_cast<const C *>(component)->view(); };
  if constexpr (has_behaviour<C>)
    node.behave = [](void *component, scope_t &scope) -> behaviour_t { return static_cast<C *>(component)->behave(scope); };
  return node;
}

// A component that takes props: a `props_t` with operator==, and a `props` member its view reads.
template <typename C>
concept has_props = component<C> && requires(C &c, const typename C::props_t &p) {
  c.props = p;
  { c.props == p } -> std::convertible_to<bool>;
};

// A child mounted with props: data flowing down from the parent's view. The child is rebuilt when
// they differ from what it has, and not otherwise -- so a parent rebuilding with the same props
// costs the child nothing.
template <has_props C>
[[nodiscard]] mount_t mount(const C &child, typename C::props_t props)
{
  using props_t = typename C::props_t;
  mount_t node = mount(child);
  node.props = std::make_shared<const props_t>(std::move(props));
  node.props_equal = [](const void *component, const void *p) -> bool { return static_cast<const C *>(component)->props == *static_cast<const props_t *>(p); };
  node.apply_props = [](void *component, const void *p) { static_cast<C *>(component)->props = *static_cast<const props_t *>(p); };
  return node;
}

// Dynamic children at stable addresses. Identity is the item itself, so there are no keys: an item
// keeps its state and its behaviours however the list around it changes. Erasing one ends its
// behaviours and frees it once they have stopped, which is a frame or so later, not at erase().
template <component T>
class list_t
{
  using items_t = std::vector<std::shared_ptr<T>>;

public:
  list_t() = default;
  list_t(list_t &&) noexcept = default;
  list_t &operator=(list_t &&) noexcept = default;
  list_t(const list_t &) = delete;
  list_t &operator=(const list_t &) = delete;

  template <typename... A>
  T &emplace_back(A &&...args)
  {
    _items.push_back(std::make_shared<T>(std::forward<A>(args)...));
    return *_items.back();
  }
  template <typename... A>
  T &emplace(std::size_t index, A &&...args)
  {
    auto it = _items.insert(_items.begin() + std::ptrdiff_t(std::min(index, _items.size())), std::make_shared<T>(std::forward<A>(args)...));
    return **it;
  }
  void erase(const T &item)
  {
    std::erase_if(_items, [&](const std::shared_ptr<T> &p) { return p.get() == &item; });
  }
  void erase_at(std::size_t index)
  {
    _items.erase(_items.begin() + std::ptrdiff_t(index));
  }
  void clear() noexcept
  {
    _items.clear();
  }
  // Move the item at `from` to `to`; nothing is rebuilt but the parent's order.
  void move(std::size_t from, std::size_t to)
  {
    auto item = std::move(_items[from]);
    _items.erase(_items.begin() + std::ptrdiff_t(from));
    _items.insert(_items.begin() + std::ptrdiff_t(std::min(to, _items.size())), std::move(item));
  }

  [[nodiscard]] std::size_t size() const noexcept
  {
    return _items.size();
  }
  [[nodiscard]] bool empty() const noexcept
  {
    return _items.empty();
  }
  [[nodiscard]] T &operator[](std::size_t i) noexcept
  {
    return *_items[i];
  }
  [[nodiscard]] const T &operator[](std::size_t i) const noexcept
  {
    return *_items[i];
  }
  // The index of an item, or size() if it is not here.
  [[nodiscard]] std::size_t index_of(const T &item) const noexcept
  {
    for (std::size_t i = 0; i < _items.size(); ++i)
    {
      if (_items[i].get() == &item)
        return i;
    }
    return _items.size();
  }

  template <typename Item, typename Base>
  class iterator_t
  {
  public:
    using value_type = T;
    using difference_type = std::ptrdiff_t;
    iterator_t() = default;
    explicit iterator_t(Base it) noexcept
      : _it(it)
    {
    }
    Item &operator*() const noexcept
    {
      return **_it;
    }
    Item *operator->() const noexcept
    {
      return _it->get();
    }
    iterator_t &operator++() noexcept
    {
      ++_it;
      return *this;
    }
    iterator_t operator++(int) noexcept
    {
      auto copy = *this;
      ++_it;
      return copy;
    }
    friend bool operator==(const iterator_t &, const iterator_t &) = default;

  private:
    Base _it{};
  };
  using iterator = iterator_t<T, typename items_t::iterator>;
  using const_iterator = iterator_t<const T, typename items_t::const_iterator>;
  iterator begin() noexcept
  {
    return iterator(_items.begin());
  }
  iterator end() noexcept
  {
    return iterator(_items.end());
  }
  const_iterator begin() const noexcept
  {
    return const_iterator(_items.begin());
  }
  const_iterator end() const noexcept
  {
    return const_iterator(_items.end());
  }

  // An item in a view. Use this rather than ui::mount(item): it shares the item's ownership, so an
  // item erased while its behaviours still run is not freed under them.
  [[nodiscard]] mount_t mount(std::size_t index) const
  {
    auto node = ui::mount(*_items[index]);
    node.keep = _items[index];
    return node;
  }
  template <typename P>
    requires has_props<T>
  [[nodiscard]] mount_t mount(std::size_t index, P &&props) const
  {
    auto node = ui::mount(*_items[index], typename T::props_t(std::forward<P>(props)));
    node.keep = _items[index];
    return node;
  }
  // Every item, in order, for a row or column's children.
  [[nodiscard]] std::vector<node_t> mount_all() const
  {
    std::vector<node_t> nodes;
    nodes.reserve(_items.size());
    for (std::size_t i = 0; i < _items.size(); ++i)
      nodes.push_back(mount(i));
    return nodes;
  }

private:
  items_t _items;
};

// What layout produced: a box, where it is, and whom it reports to. This is the hit-test list,
// one entry per box in logical units; a renderer reads display_list_t instead (G24).
struct draw_item_t
{
  rect_t rect;
  color_t color;
  const box_t *box = nullptr;
  detail::slot_t *slot = nullptr;
  int ordinal = 0;
};

// ---------------------------------------------------------------------------------------------
// The display list (gui/PLAN.md, "Rendering")

enum class prim_kind_t : std::uint32_t
{
  // A rounded rectangle with an optional border, or with `blur` > 0 a Gaussian-blurred one, which
  // is a shadow. x, y, width and height are logical units.
  shape = 0,
  // A rectangle of the glyph atlas, copied texel for texel and tinted with `fill`: a glyph or an
  // icon (G39). x and y are a logical anchor, which the shader rounds to a whole pixel; width and
  // height are pixels; radii are the atlas texel the rectangle starts at (0, 1) and the pixel
  // offset of its top left from the rounded anchor (2, 3). Every glyph of one text node shares the
  // anchor, so they all round the same way and the spacing HarfBuzz gave them survives.
  coverage = 1,
  // A line segment with round ends: from (x, y) to (radii[0], radii[1]), `border_width` wide, in
  // `fill`; all logical units. A polyline is one per segment (G41).
  segment = 2,
  // The area under a segment: from x to radii[0] across, below the line from (x, y) to
  // (radii[0], radii[1]) and down to radii[2]. Antialiased along the line only, so the areas of
  // neighbouring segments, which share an x exactly, meet without a seam or an overlap.
  area = 3,
};

// One primitive: an instanced quad whose shape the fragment shader computes. Relative to the origin
// of the run it is drawn in. 80 bytes, laid out for a vertex buffer read at instance rate.
struct prim_t
{
  float x = 0;
  float y = 0;
  float width = 0;
  float height = 0;
  // Top-left, top-right, bottom-right, bottom-left; for coverage, see prim_kind_t.
  float radii[4] = {0, 0, 0, 0};
  color_t fill;
  color_t border_color = {0, 0, 0, 0};
  float border_width = 0;
  float blur = 0;
  prim_kind_t kind = prim_kind_t::shape;
  float reserved = 0;
};
static_assert(sizeof(prim_t) == 80);

// The glyph atlas as a renderer sees it: one byte of coverage per texel, rows top to bottom. A
// renderer that last saw `generation` uploads only `dirty`; any other generation is a new atlas and
// is uploaded whole.
struct atlas_view_t
{
  std::span<const std::uint8_t> pixels;
  extent_t extent;
  rect_t dirty;
  std::uint64_t generation = 0;
};

// A range of prims drawn at one origin. Moving a chunk changes its origin and nothing else (G29).
struct run_t
{
  std::uint32_t first = 0;
  std::uint32_t count = 0;
  float x = 0;
  float y = 0;
};

// One frame's worth of drawing, in painter's order. `prims` is assembled afresh every frame from
// cached chunks; only what changed was regenerated.
struct display_list_t
{
  std::span<const prim_t> prims;
  std::span<const run_t> runs;
  color_t background;
  // Layout units. framebuffer / logical is the scale the renderer applies.
  extent_t logical;
  extent_t framebuffer;
  float scale = 1;
  atlas_view_t atlas;
};

// A Vulkan device the program already has, for the renderer to share rather than create its own
// (G31). Handles are the Vulkan ones, passed as pointers so this header needs no vulkan.h.
struct vulkan_device_t
{
  void *instance = nullptr;
  void *physical_device = nullptr;
  void *device = nullptr;
  void *queue = nullptr;
  std::uint32_t queue_family = 0;
  void (*(*get_instance_proc_addr)(void *instance, const char *name))() = nullptr;
};

enum class render_api_t : std::uint8_t
{
  // Vulkan when it can be loaded and a device made, else the GL stopgap, else nothing.
  automatic,
  vulkan,
  gl,
};

struct run_config_t
{
  color_t background = {0.12f, 0.12f, 0.14f, 1};
  // Draw at all. Without a renderer (the null backend has none) nothing is drawn, and everything
  // else -- views, layout, input, behaviours -- still runs.
  bool draw = true;
  render_api_t api = render_api_t::automatic;
  // Share the program's Vulkan device. Without one the renderer creates and owns its own.
  std::optional<vulkan_device_t> vulkan_device;
  // Commands per chunk before a subtree holds its own (G29). Tests lower it.
  std::size_t chunk_threshold = 128;
  // The font for text that names none. Empty: font_t::system_default(), looked up once.
  font_t font;
  // Called after every layout with the hit-test list it produced.
  std::function<void(std::span<const draw_item_t>)> on_layout;
  // Called after every layout with the display list, whether or not anything draws it.
  std::function<void(const display_list_t &)> on_display_list;
  // Called once, with which renderer was chosen ("vulkan: <device>", "gl") or why none was.
  std::function<void(std::string_view)> on_renderer;
};

namespace detail
{
vio::task_t<void> run_root(window_t &window, mount_t root, run_config_t config);

template <component C>
vio::task_t<void> run_owned(window_t &window, C root, run_config_t config)
{
  co_await run_root(window, mount(root), std::move(config));
}
} // namespace detail

// Show `root` in `window` until the window closes, then end every behaviour and return. Taking an
// lvalue, the caller owns the component and must keep it alive until the task completes; taking an
// rvalue, the task owns it.
template <component C>
[[nodiscard]] vio::task_t<void> run(window_t &window, C &root, run_config_t config = {})
{
  return detail::run_root(window, mount(root), std::move(config));
}

template <component C>
  requires(!std::is_lvalue_reference_v<C>)
[[nodiscard]] vio::task_t<void> run(window_t &window, C &&root, run_config_t config = {})
{
  return detail::run_owned<std::remove_cvref_t<C>>(window, std::move(root), std::move(config));
}
} // namespace vio::gui::ui
