#include <doctest/doctest.h>

#include <vio/event_loop.h>
#include <vio/operation/tcp.h>

#include <uv.h>

namespace
{
// dealloc_cb_t is a plain function pointer, so accounting is threaded through
// the user_ptr argument (which read_cb passes as read.alloc_cb_data).
void counting_dealloc(void *user_ptr, uv_buf_t *buf)
{
  if (user_ptr != nullptr)
  {
    ++*static_cast<int *>(user_ptr);
  }
  delete[] buf->base;
  buf->base = nullptr;
  buf->len = 0;
}
} // namespace

TEST_SUITE("tcp read_cb")
{
  // Per libuv's uv_read_cb contract, nread == 0 means EAGAIN/EWOULDBLOCK and
  // must be treated as a no-op -- NOT as end-of-stream. Regression test for the
  // read_cb else-branch fabricating a UV_EOF error on a healthy socket.
  TEST_CASE("nread==0 is EAGAIN, not a fabricated EOF")
  {
    vio::event_loop_t loop;
    {
      // Construct the state directly (no uv_tcp_init / no registered closable
      // handle) so dropping the ref is a plain delete needing no loop tick.
      auto state = vio::ref_ptr_t<vio::tcp_state_t>(loop);

      int dealloc_count = 0;
      state->read.alloc_cb_data = &dealloc_count;
      state->read.dealloc_buffer_cb = counting_dealloc;
      state->read.continuation = nullptr;

      auto *stream = state->get_stream();

      // Park a strong ref into stream->data exactly as uv_read_start would.
      auto parked = state;
      stream->data = parked.release_to_raw();

      uv_buf_t buf{};
      buf.base = new char[64];
      buf.len = 64;

      // Simulate libuv delivering an EAGAIN tick.
      vio::tcp_reader_t::read_cb(stream, 0, &buf);

      // EAGAIN must not enqueue anything and must not surface an error.
      CHECK(state->read.buffer_queue.empty());
      // The supplied buffer must still be released.
      CHECK_EQ(dealloc_count, 1);

      // Recover the parked ref so the storage refcount balances.
      vio::ref_ptr_t<vio::tcp_state_t>::from_raw(stream->data);
      stream->data = nullptr;
    }

    loop.stop();
    loop.run();
  }

  // A genuine EOF (nread < 0) must still enqueue an error so the reader wakes.
  TEST_CASE("nread<0 still reports EOF")
  {
    vio::event_loop_t loop;
    {
      auto state = vio::ref_ptr_t<vio::tcp_state_t>(loop);

      int dealloc_count = 0;
      state->read.alloc_cb_data = &dealloc_count;
      state->read.dealloc_buffer_cb = counting_dealloc;
      state->read.continuation = nullptr;

      auto *stream = state->get_stream();
      auto parked = state;
      stream->data = parked.release_to_raw();

      uv_buf_t buf{};
      buf.base = new char[64];
      buf.len = 64;

      vio::tcp_reader_t::read_cb(stream, UV_EOF, &buf);

      REQUIRE_EQ(state->read.buffer_queue.size(), 1);
      CHECK_FALSE(state->read.buffer_queue.front().has_value());
      CHECK_EQ(state->read.buffer_queue.front().error().code, UV_EOF);
      CHECK_EQ(dealloc_count, 1);

      vio::ref_ptr_t<vio::tcp_state_t>::from_raw(stream->data);
      stream->data = nullptr;
    }

    loop.stop();
    loop.run();
  }
}
