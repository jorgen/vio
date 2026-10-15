/*
  Copyright (c) 2025 Jorgen Lind

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

#include "vio/error.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <functional>
#include <vector>

#include "vio/errc.h"

namespace vio
{

constexpr int vio_cancelled = 0xca9ce1;

inline bool is_cancelled(const error_t &err)
{
  return err.code == vio_cancelled || err.code == errc::canceled;
}

class cancellation_t;

class registration_t
{
public:
  registration_t() = default;

  registration_t(const registration_t &) = delete;
  registration_t &operator=(const registration_t &) = delete;

  registration_t(registration_t &&other) noexcept
    : _cancel(other._cancel)
    , _id(other._id)
  {
    other._cancel = nullptr;
    other._id = 0;
    rebind();
  }

  registration_t &operator=(registration_t &&other) noexcept
  {
    if (this != &other)
    {
      deregister();
      _cancel = other._cancel;
      _id = other._id;
      other._cancel = nullptr;
      other._id = 0;
      rebind();
    }
    return *this;
  }

  ~registration_t()
  {
    deregister();
  }

  void reset()
  {
    deregister();
  }

  [[nodiscard]] bool active() const noexcept
  {
    return _cancel != nullptr;
  }

private:
  friend class cancellation_t;

  registration_t(cancellation_t *cancel, uint64_t id)
    : _cancel(cancel)
    , _id(id)
  {
    rebind();
  }

  inline void deregister() noexcept;
  inline void rebind() noexcept;

  void detach() noexcept
  {
    _cancel = nullptr;
    _id = 0;
  }

  cancellation_t *_cancel = nullptr;
  uint64_t _id = 0;
};

class cancellation_t
{
public:
  cancellation_t() = default;
  cancellation_t(const cancellation_t &) = delete;
  cancellation_t &operator=(const cancellation_t &) = delete;
  cancellation_t(cancellation_t &&) = delete;
  cancellation_t &operator=(cancellation_t &&) = delete;

  ~cancellation_t()
  {
    for (auto &entry : _callbacks)
    {
      if (entry.owner)
        entry.owner->detach();
    }
  }

  void cancel()
  {
    if (_cancelled)
      return;
    _cancelled = true;
    auto callbacks = std::move(_callbacks);
    _callbacks.clear();
    for (auto &entry : callbacks)
    {
      if (entry.owner)
        entry.owner->detach();
      entry.owner = nullptr;
    }
    for (auto &entry : callbacks)
    {
      entry.fn();
    }
  }

  [[nodiscard]] bool is_cancelled() const
  {
    return _cancelled;
  }

  registration_t register_callback(std::function<void()> fn)
  {
    auto id = ++_next_id;
    _callbacks.push_back({id, std::move(fn), nullptr});
    return {this, id};
  }

private:
  friend class registration_t;

  struct callback_entry_t
  {
    uint64_t id;
    std::function<void()> fn;
    registration_t *owner;
  };

  callback_entry_t *find(uint64_t id) noexcept
  {
    for (auto &entry : _callbacks)
    {
      if (entry.id == id)
        return &entry;
    }
    return nullptr;
  }

  void remove_callback(uint64_t id) noexcept
  {
    _callbacks.erase(std::remove_if(_callbacks.begin(), _callbacks.end(), [id](const callback_entry_t &e) { return e.id == id; }), _callbacks.end());
  }

  std::vector<callback_entry_t> _callbacks;
  uint64_t _next_id = 0;
  bool _cancelled = false;
};

inline void registration_t::deregister() noexcept
{
  if (_cancel)
  {
    _cancel->remove_callback(_id);
    _cancel = nullptr;
    _id = 0;
  }
}

inline void registration_t::rebind() noexcept
{
  if (!_cancel)
    return;
  if (auto *entry = _cancel->find(_id))
    entry->owner = this;
  else
    detach();
}

} // namespace vio
