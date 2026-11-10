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
#include <cstdint>
#include <deque>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <span>
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

struct box_t
{
  extent_t size;
  color_t color;
  event_ref_t events;
  // A one-line handler. It runs when the box is pressed, and its component is rebuilt after it.
  // For anything that spans several events, subscribe in behave() instead.
  std::function<void()> on_press;
};

struct row_t
{
  int gap = 0;
  std::vector<node_t> children;
};

struct column_t
{
  int gap = 0;
  std::vector<node_t> children;
};

// A child component in its parent's output. It refers to the child; it does not hold its nodes, so
// rebuilding the parent does not rebuild the child.
struct mount_t
{
  void *component = nullptr;
  node_t (*view)(const void *component) = nullptr;
  behaviour_t (*behave)(void *component, scope_t &scope) = nullptr;
};

struct node_t : std::variant<box_t, row_t, column_t, mount_t>
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
    if (scope_cancelled(*_scope))
      return false;
    return _inner.await_ready();
  }

  template <typename Promise>
  std::coroutine_handle<> await_suspend(std::coroutine_handle<Promise> frame)
  {
    if (scope_cancelled(*_scope))
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

// The coroutine type of behave() and of everything spawned into a scope. Unlike task_t it is lazy:
// scope_t::spawn starts it. The promise finds its scope among the coroutine's parameters -- the
// first, or the second after a member function's object -- so a behaviour without a scope_t &
// parameter does not compile.
class behaviour_t
{
public:
  struct promise_type
  {
    template <typename... Rest>
    explicit promise_type(scope_t &scope, Rest &...) noexcept
      : scope(&scope)
    {
    }
    template <typename Self, typename... Rest>
      requires(!std::same_as<std::remove_cvref_t<Self>, scope_t>)
    promise_type(Self &, scope_t &scope, Rest &...) noexcept
      : scope(&scope)
    {
    }

    behaviour_t get_return_object() noexcept
    {
      return behaviour_t(std::coroutine_handle<promise_type>::from_promise(*this));
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
      void await_suspend(std::coroutine_handle<promise_type> frame) noexcept
      {
        detail::scope_finished(*frame.promise().scope, frame);
      }
      void await_resume() const noexcept
      {
      }
    };
    final_t final_suspend() noexcept
    {
      return {};
    }
    void return_void() noexcept
    {
    }
    void unhandled_exception() noexcept
    {
      std::terminate();
    }

    template <typename A>
    auto await_transform(A &&awaitable)
    {
      return detail::guarded_t(std::forward<A>(awaitable), *scope);
    }

    scope_t *scope;
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
  scope_t(const scope_t &) = delete;
  scope_t &operator=(const scope_t &) = delete;
  ~scope_t()
  {
    assert(_running.empty() && "a scope was destroyed with behaviours still running");
  }

  // Start a behaviour in this scope. It runs to its first suspension before spawn returns, and it
  // belongs to the scope, not to whoever spawned it.
  void spawn(behaviour_t behaviour);

  // Rebuild this component's view at the next frame. Resuming a behaviour already does this; call
  // it for a change made where no behaviour woke up.
  void invalidate() noexcept;

  [[nodiscard]] vio::event_loop_t &loop() const noexcept;

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

  void cancel();
  void forget(std::coroutine_handle<> frame) noexcept;

  detail::runtime_t *_runtime;
  detail::slot_t *_slot;
  vio::cancellation_t _token;
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

// What layout produced: a box, where it is, and whom it reports to. Exposed for tests and for a
// renderer other than the built-in one.
struct draw_item_t
{
  rect_t rect;
  color_t color;
  const box_t *box = nullptr;
  detail::slot_t *slot = nullptr;
  int ordinal = 0;
};

struct run_config_t
{
  color_t background = {0.12f, 0.12f, 0.14f, 1};
  // Draw with OpenGL. Without a GL context (the null backend) nothing is drawn, and everything
  // else -- views, layout, input, behaviours -- still runs.
  bool draw = true;
  // Called after every layout with what it produced.
  std::function<void(std::span<const draw_item_t>)> on_layout;
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
