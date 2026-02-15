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
#include <functional>
#include <vector>

#include <uv.h>

namespace vio
{

constexpr int vio_cancelled = 0xca9ce1;

inline bool is_cancelled(const error_t &err)
{
  return err.code == vio_cancelled || err.code == UV_ECANCELED;
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

private:
  friend class cancellation_t;

  registration_t(cancellation_t *cancel, uint64_t id)
    : _cancel(cancel)
    , _id(id)
  {
  }

  inline void deregister();

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
  ~cancellation_t() = default;

  void cancel()
  {
    if (_cancelled)
      return;
    _cancelled = true;
    auto callbacks = std::move(_callbacks);
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
    _callbacks.push_back({id, std::move(fn)});
    return {this, id};
  }

private:
  friend class registration_t;

  void remove_callback(uint64_t id)
  {
    _callbacks.erase(std::remove_if(_callbacks.begin(), _callbacks.end(), [id](const callback_entry_t &e) { return e.id == id; }), _callbacks.end());
  }

  struct callback_entry_t
  {
    uint64_t id;
    std::function<void()> fn;
  };

  std::vector<callback_entry_t> _callbacks;
  uint64_t _next_id = 0;
  bool _cancelled = false;
};

inline void registration_t::deregister()
{
  if (_cancel)
  {
    _cancel->remove_callback(_id);
    _cancel = nullptr;
    _id = 0;
  }
}

} // namespace vio
