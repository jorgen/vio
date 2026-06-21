# vio — Memory & Control-Flow Review

Scope: allocation cost per *logical operation* and per *recurring event*, control/data-flow
correctness, data-structure choices, and lifetime/ownership safety across the libuv C-callback
boundary. Header tree under `src/vio/`.

Method: 6 per-subsystem allocation+flow deep-dives → per-finding adversarial verification →
3 whole-library cross-cutting lenses (lifetime, alloc-accounting, data structures) → completeness
critic → synthesis. **The auto-verification confirmed everything and refuted nothing, so the
top lifetime claims were re-checked by hand against the source** — see "Verification note" below.

---

## Verdict

The memory model is fundamentally sound and quite good:

- `ref_ptr_t<Data>` fuses the control block and the payload into **one** `new storage_t`
  (make_shared-style). One allocation per ref-counted object, not two.
- `future_t`-style operations (sleep, dns, file, work) return the ref-counted state which *doubles
  as the awaiter* — **no extra awaiter frame** per await.
- Ownership is shuttled across the uv C boundary with a `release_to_raw()`/`from_raw()` pair, and
  `release_to_raw()` is deliberately non-decrementing so a callback can borrow the parked ref and
  re-park it without touching the count.

The weaknesses are: (1) the boundary-ownership discipline is manual and unprotected by
type/RAII/asserts — that fragility produced two genuine refcount bugs; (2) the dominant
steady-state allocation is an **unpooled 64 KB buffer per readable event**; (3) `reference_counted_t`
bakes **1–3 unavoidable first-push `std::vector` allocations into every handle**; and (4) a handful
of recurring control-plane allocations (event-pipe drain, the `detached_task_t` driver frame,
`std::vector`-as-FIFO front-erase).

---

## Verification note (important)

| Finding | Auto-verdict | Hand-check | Result |
|---|---|---|---|
| #1 `read_cb`/`recv_cb` "double-free" | critical/confirmed | re-derived refcount | **FALSE POSITIVE** |
| #2 `tcp_listen` over-release | critical/confirmed | tcp_server.h:71–93 | **CONFIRMED** |
| #3 DNS sync-failure leak | high/confirmed | dns.h vs file.h:204 | **CONFIRMED** |
| #6 TCP `nread==0` EOF | medium/confirmed | tcp.h:429–443 vs udp.h:427 | **CONFIRMED** |

Why #1 is a false positive: in `read_cb`/`recv_cb` the parked ref is adopted with `from_raw` and
re-parked by a scope-exit `ref_ptr_releaser_t` whose dtor calls `release_to_raw()` (no decrement).
If the resumed continuation destroys the reader, `~tcp_reader_t` does `from_raw(stream->data)` and
that local `state` decrements once at dtor end, together with the reader's own `handle` member —
exactly the two refs the reader created (handle member + parked). The callback's borrowed ref is
released, not decremented. Net: the parked ref is decremented exactly once. No double-decrement,
no double-free. `release_to_raw()` never dereferences storage, so the "UAF in the releaser" path
does not exist. **#2 is a real bug for the same reason #1 is safe**: `on_connection` consumes the
parked ref with a bare `from_raw` and **no** balancing `release_to_raw`, and `uv_listen` fires more
than once.

---

## Allocation per logical operation / per event (happy path)

| operation / event | heap allocs | breakdown | avoidable? |
|---|---|---|---|
| `make_ref_ptr<Data>()` | 1 | `new storage_t` (control block + Data fused); destroyer fn is SBO | no (the 1 is mandatory) |
| `register_closable_handle` (1st) | 1 | `closable_handles` vector first push | **yes** (inline-1) |
| `register_destroy_callback` (1st) | 0–1 | `destroy_callbacks` vector first push (+0–1 fn if capture > SBO) | **yes** (vector) |
| ref inc / copy | 0 | relaxed atomic fetch_add | n/a |
| ref dec / teardown | 0 | swap is alloc-free; uv_close uses preallocated handles | n/a |
| call a `task_t<T>` coroutine | 1 | compiler `operator new` for the (eager) frame | no |
| `run_in_loop(coroutine)` submit | ~3 | 1 user frame + **1 `detached_task_t` driver frame** + 0–1 fn | **driver frame yes** |
| `sleep(d)` | 1 [+1 cancel] | state storage (uv_timer_t inline) [+ cancellation vector 1st push] | no [cancel: yes] |
| `dns get_addrinfo` | 1 + host-copy + result-vec + N·(addr-vec + canonname) | state; **dead `host` std::string copy**; result.reserve(5); per-addr `vector<uint8_t>` | **host-copy yes**; per-addr yes |
| `file open/close/stat/...` | 0 (vio) | stack `uv_fs_t` | — but `open_file` leaks the libuv wide-path buffer (no `uv_fs_req_cleanup`, Windows) |
| `file read/write/sendfile` | 1 [+1 cancel] | state storage (uv_fs_t inline); user buffer | no [cancel: yes] |
| `work` submit (N items) | ~2 + 2N | batch state + results vec + **N `make_shared<packaged_task>`** + N fn + 1 completion fn | **the N packaged_task yes** (futures discarded) |
| `tcp_create` | 2 | state storage + closable_handles vector | 1 (closable vector) |
| `tcp connect` (existing sock) | 0 [+1 cancel] | release/from_raw are pointer moves; inc only | n/a |
| `tcp write` (existing sock) | 0 | embedded `uv_write_t` reused; refcount only | n/a (but no in-flight guard) |
| `tcp create_reader` | 0 | reuses state ref | n/a |
| **tcp/udp read fill (per readable event)** | **1–2** | **1× `new char[65536]`** + amortized buffer_queue vector growth | **64 KB yes (pool/right-size); vector yes (ring/deque)** |
| tcp/udp read consume (`await_resume`) | 0 | but **O(n) `erase(begin())`** front-shift of `std::vector` FIFO | shift yes (deque/ring) |
| `tcp accept` (per connection) | 2 | new tcp_state storage + closable_handles vector | 1 (closable vector) |
| `ssl_client_create` | ~6 + CA copy | state + closable vec + destroy vec + elastic_index_storage(_data + 2 bitsets) + tls_config + ctx; **+100–300 KB CA bundle std::string copy** | 3–4 (vectors, CA copy, per-conn tls_config) |
| `ssl_server_create` | ~5 + CA copy | state + tls_config + ctx + destroy vec; **+ CA bundle copy** | CA copy + per-server tls_config |
| `ssl_server_accept` | ~4–5 | client state + per-client tls obj + tcp_state + control-block vectors | control-block vectors |
| tls/tcp write (steady) | 0–1 | elastic_index_storage `activate()`: `std::queue`/deque node (MSVC reallocs); 0 if <PreferredSize in flight | deque node yes (ring of indices) |
| **event_pipe drain (per async wakeup)** | **1 malloc + 1 free** | reserve-after-swap reallocates events buffer every drain + scope-exit free | **yes (ping-pong scratch)** |
| `post_event` (producer) | 0 | amortized emplace_back; uv_async_send | n/a |
| `about_to_block_cb` (every loop iter) | 0 | range-for | n/a (good) |
| `awaitable_event_pipe.call()` (cross-loop RPC) | 1 [+1 if coroutine handler] | `make_shared<call_state_t>` [+ `detached_task_t` frame] | handler driver frame yes |
| TLS handshake | 0 (vio) | driven lazily inside first tls_read/write; buffers libressl-internal | n/a |
| cancellation register/deregister | 0–1 | vector 1st push; fn SBO; **O(n) remove** on deregister | vector 1st push; swap-and-pop |

---

## Confirmed correctness / lifetime issues

### C1 — `tcp_listen` over-releases the parked ref → UAF on 2nd+ connection  *(tcp_server.h:71–93)*
`on_connection` does `from_raw(stream->data)` (consuming) but never nulls `stream->data`; the
`if (!stream->data) return;` guard at :73 therefore never fires. `uv_listen` fires once per pending
connection, so a second connection re-consumes the same `storage_t*` → over-decrement → UAF. The
cancel callback at :113–119 shows the correct pattern (consume once **and** null `stream->data`).
**Fix:** on the already-done/normal path, peek state via a non-owning cast (no decrement); consume
the ref exactly once at teardown and null `stream->data` the instant it is consumed.

### C2 — DNS `get_addrinfo`/`get_nameinfo` leak the parked ref on synchronous failure  *(dns.h:177–183, 272–278)*
Both park a ref via `release_to_raw` (:152/:249) recovered only by the uv callback. When
`uv_getaddrinfo`/`uv_getnameinfo` return `r<0` synchronously the callback never runs, but the
early-return only sets `done`/`result` — the whole `storage_t` (state + `host` string + result
vector) leaks. `file.h:204` does this correctly. **Fix:** add `future_ref_ptr_t::from_raw(req.data);`
in both `r<0` branches and null `req->data`.

### C3 — TCP `read_cb` treats `nread==0` (EAGAIN) as EOF  *(tcp.h:429–443)*
The `else` branch covers both `nread<0` and `nread==0`; for `nread==0` `code` stays `UV_EOF`, an
error is pushed and the continuation resumed — fabricating end-of-stream on a healthy socket.
Per libuv's `uv_read_cb` contract `nread==0` is EAGAIN and must be a no-op. UDP guards this
correctly at udp.h:427–434; TCP omits it (`uv_strerror(0)` = "Success" is the tell). **Fix:** add the
`nread==0` early-return guard mirroring UDP.

### C4 — `write_tcp` has no in-flight guard (latent)  *(tcp.h:278–305)*
`tcp_state_t` has a single embedded `uv_write_t`; `write_tcp` reuses it with no guard (unlike
`tcp_connect`, which guards on `connect.started`). A second concurrent write clobbers `write.req`
(leaks the first parked ref) and corrupts the in-flight request → UB. Latent because callers
serialize today. **Fix:** guard on `write.started && !write.done`, or allocate per-write `uv_write_t`
via `elastic_index_storage` like `socket_stream`.

### C5 — TLS unclean-close detection documented but absent  *(tls_common.h:157–160; socket_stream.h:287–294)*
CLAUDE.md:219–222 documents a `recv(fd, buf, 1, MSG_PEEK)` probe on `TLS_WANT_POLLIN` to detect a
peer that closes TCP without `close_notify`. The code has no such probe (grep confirms no
`MSG_PEEK` in `src/vio`); the reader polls forever. The `UV_DISCONNECT` fallback only stops the
poll and returns — it never sets `read_buffer_error` or resumes the continuation. **Fix:** restore
the probe (or make the `UV_DISCONNECT` path resume with an error), then reconcile CLAUDE.md.

### C6 — `open_file` never calls `uv_fs_req_cleanup` → per-open wide-path leak on Windows  *(file.h:75–104)*
Every other sync fs wrapper cleans up; `open_file` (both paths) and `close_file` do not. On Windows
`uv_fs_open` always allocates a UTF-16 path buffer freed only by `uv_fs_req_cleanup`. Leaks on every
open on the primary platform. **Fix:** add `uv_fs_req_cleanup(&request)` on success and error paths.

### C7 — `ssl_config_t::verify_depth` is `std::optional<bool>` but used as a chain depth  *(ssl_config_t.h:45; tls_common.h:116–118)*
Passed to `tls_config_set_verify_depth` (an `int`), so any configured depth ≥2 silently collapses to
1. Almost certainly a typo. **Fix:** change to `std::optional<int>`.

### C8 — reader `cancel()` doesn't stop uv delivery; 64 KB buffers keep accumulating  *(tcp.h:352–369; udp.h:356–373)*
`cancel()` sets the flag, enqueues one ECANCELED, resumes — but never calls
`uv_read_stop`/`uv_udp_recv_stop` nor clears `started`. libuv keeps delivering, each delivery a
64 KB alloc into an unbounded queue until the reader is destroyed. **Fix:** stop delivery in
`cancel()` (reclaim parked ref, `uv_read_stop`, clear `started`/`active`) and early-return in the
callback when cancelled.

### C9 — cross-thread `dec()` races the non-atomic teardown fields  *(ref_counted_impl.h:18,33–67; work.h:109–110)*
`ref_count` is an `acq_rel` atomic, but `in_destroy_sequence`, `close_pending`, and the two vectors
assume single-threaded execution. `schedule_work` captures a `ref_ptr<work_batch_state_t>` in the
worker lambda; when the lambda finishes **on the worker thread** that ref is destroyed there — a
genuine cross-thread `dec()` of state shared with the loop thread. `uv_close` must also run only on
the loop thread. **Fix:** require/assert that the final release runs on the loop thread; marshal the
worker's state release back through `run_in_loop`.

---

## Top memory / efficiency improvements (ranked)

1. **Buffer pool behind the existing `alloc_cb`/`dealloc_cb` hooks** *(socket_stream.h:414, unique_buf.h:88, tcp.h:476, udp.h:491)* — the 64 KB-per-event `new char[65536]` is the dominant steady-state read cost across tcp/tls/udp; the hooks already thread a `user_alloc_ptr`, so a per-loop free-list is a drop-in with no API change. Also replace the magic `65536` with a named constant and consider FIONREAD right-sizing.
2. **Shrink `reference_counted_t`'s two vectors to small/inline storage** *(ref_counted_impl.h:15–16)* — 1 alloc/tcp socket, ~2/TLS client, 1–2/accept, all unconditional first-pushes. Highest-leverage after read buffers on accept-heavy servers. Must preserve `dec()`'s swap+reverse-iterate of `destroy_callbacks` and the *re-entrant append to `closable_handles` during destroy-callback iteration* (tls_client.h:264 / tls_server.h:212 push the poll handle mid-teardown).
3. **Unify the read FIFO** *(tcp.h:71/392, udp.h:79/396)* — `std::vector` + `erase(begin())` is O(n) and unbounded under backpressure. Use `ring_buffer_t` (as `socket_stream` already does) or `std::deque`, plus watermark flow control (`uv_read_stop`/recv pause).
4. **CA trust store by reference** *(tls_client.h:59, tls_server.h:58, library.cpp:136/144)* — `get_default_ca_certificates()` returns `std::string` by value; each connection copies the 100–300 KB root bundle (twice). Return `const std::string&` and drop the per-conn `cert_data` member; libressl copies the bytes anyway.
5. **event_pipe drain: reuse capacity** *(event_pipe_impl.h:61–66)* — `reserve()` after `swap()` reallocates every drain (1 malloc + 1 free per async wakeup). Keep a persistent scratch buffer and `clear()`-then-`swap` it. **Do not** hold `_mutex` during the callback loop (the existing lock-drop ordering prevents `post_event` re-entrancy deadlock).
6. **`run_in_loop(coroutine)` second frame** *(event_loop_impl.h:80–89; awaitable_event_pipe.h:110–114; wasm event_loop_impl.h:52)* — give `task_t` a self-destroying `detach()` so the eager frame frees itself at `final_suspend`, eliminating the `detached_task_t` driver frame. (Do **not** use a `noop_coroutine` continuation — that leaks the user frame.)
7. **`schedule_work` discarded `packaged_task`** *(thread_pool.h:80–100; work.h:107–139)* — N `make_shared<packaged_task>` per batch whose futures are ignored. Add a fire-and-forget `enqueue` overload taking a move-only callable.
8. **`elastic_index_storage` write_queue churn** *(elastic_index_storage.h:37–42,76–80)* — eager 3-alloc ctor even for read-only sockets; per-write deque node on MSVC; `deactivate()` shrinks to `PreferredSize` every time → grow/shrink thrash. Lazy-init, shrink target 0 (or hysteresis), replace `std::queue` with a reusable ring of indices.

---

## Quick wins (trivial / small, high value)

- DNS: add `from_raw(req.data)` in the `r<0` branches (dns.h:177, 272) — fixes a definite leak. **[C2]**
- `tcp_listen`: peek non-owning on the done path + null `stream->data` on consume (tcp_server.h:73–78). **[C1]**
- TCP `read_cb`: add the `nread==0` guard (tcp.h:429–443). **[C3]**
- `open_file`: add `uv_fs_req_cleanup(&request)` (file.h:96–104). **[C6]**
- `verify_depth`: `std::optional<bool>` → `std::optional<int>` (ssl_config_t.h:45). **[C7]**
- `get_default_ca_certificates()`: return `const std::string&` (library.cpp:136/144). **[#4]**
- `ring_buffer_t::emplace()` returns the **wrong slot** and copies args by value — currently dead code (socket_stream uses push/replace_back) but a live trap. Fix to capture index before advancing + `std::forward`, or delete it (ring_buffer.h:96–103).
- Dead state to remove: `event_loop_t::_mutex` (event_loop_impl.h:175), `tcp_read_state_t::cancelled` (tcp.h:70), `udp_recv_state_t::cancelled` (udp.h:78), `get_addrinfo_state_t::host` (dns.h:106/147 — copied but never used).
- socket_stream.h:357 — parenthesize the mixed `&&`/`||` resume guard (operator-precedence trap). socket_stream.h:616 — pass `stream->user_alloc_ptr` instead of `nullptr` to `dealloc_cb`.
- event_loop_impl.h:170 — redundant trailing `uv_prepare_stop` after the `uv_close` loop.

---

## Architecture recommendations

- **Formalize the uv-boundary transfer with a typed RAII slot** (e.g. `handle_slot_t<Data>` with
  symmetric `store()`/`take()`, debug-poison + assert on double-`take`). Both confirmed lifetime
  bugs (C1, and the absence of the bug in #1) are about exactly-once pairing of park/consume — a
  type would catch the mis-pairing at runtime. Highest-value structural change for safety.
- **Per-loop buffer pool** as the default read allocator (see #1 above).
- **Small-buffer `reference_counted_t`** (see #2 above).
- **One read-queue type + flow control** shared by tcp/udp/socket_stream (see #3 above).
- **Document & assert the threading contract**: `dec()`-to-zero, `uv_close`, and the non-atomic
  teardown fields run on the loop thread; marshal worker releases back via `run_in_loop`.
- **Self-destroying `task_t::detach()`** to drop the second coroutine frame on every submission.
- **Debug outstanding-frame counter** (inc in `get_return_object`, dec in `destroy`, assert zero at
  loop teardown) to catch the by-design abandoned-suspended-task leak under tests/ASan.
- **Audit the WASM platform layer** (`platform/wasm/*`) — unanalyzed; replicates the
  `detached_task_t` double-frame and does a raw `new timer_data_t` per sleep.
- **Reconcile CLAUDE.md** with the missing TLS unclean-close probe (C5).

---

## Notes

- `crypto.h`, `bit_mask.h`, `auto_closer.h`, `uv_coro.h`, `dynamic_bitset.h`, `about_to_block.h`
  were read and found correct/zero-issue. `uv_coro.h`'s `future_t<STATE>` does exactly one
  `make_ref_ptr<STATE>()` per op — the single per-op state allocation the table attributes.
- The defensive `closed` re-checks in `socket_stream::on_poll_event` (a write completion can resume
  a coroutine that destroys the stream) are correct and a genuine strength.
- Build verified: `cmake -B build -G Ninja && cmake --build build` → 76/76, exit 0; tests link.
