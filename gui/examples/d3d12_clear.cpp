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

#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif

#include <array>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <print>

#include <vio/gui/context.h>
#include <vio/gui/gui.h>
#include <vio/run.h>

#include <windows.h>

#include <d3d12.h>
#include <dxgi1_6.h>

namespace gui = vio::gui;

namespace
{
template <typename T>
void release(T *&pointer)
{
  if (pointer)
    pointer->Release();
  pointer = nullptr;
}

struct renderer_t
{
  static constexpr UINT buffers = 2;

  ID3D12Device *device = nullptr;
  ID3D12CommandQueue *queue = nullptr;
  ID3D12CommandAllocator *allocator = nullptr;
  ID3D12GraphicsCommandList *list = nullptr;
  ID3D12DescriptorHeap *heap = nullptr;
  ID3D12Fence *fence = nullptr;
  HANDLE event = nullptr;
  UINT64 fence_value = 0;
  UINT descriptor_size = 0;
  IDXGISwapChain3 *swap_chain = nullptr;
  std::array<ID3D12Resource *, buffers> targets{};

  ~renderer_t()
  {
    wait();
    for (auto *&target : targets)
      release(target);
    release(swap_chain);
    release(fence);
    release(heap);
    release(list);
    release(allocator);
    release(queue);
    release(device);
    if (event)
      CloseHandle(event);
  }

  bool create(gui::window_t &window)
  {
    if (FAILED(D3D12CreateDevice(nullptr, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&device))))
    {
      IDXGIFactory4 *factory = nullptr;
      IDXGIAdapter *warp = nullptr;
      if (FAILED(CreateDXGIFactory1(IID_PPV_ARGS(&factory))) || FAILED(factory->EnumWarpAdapter(IID_PPV_ARGS(&warp))))
        return false;
      const bool made = SUCCEEDED(D3D12CreateDevice(warp, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&device)));
      release(warp);
      release(factory);
      if (!made)
        return false;
      std::println("using the WARP software adapter");
    }
    D3D12_COMMAND_QUEUE_DESC queue_description{};
    queue_description.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
    device->CreateCommandQueue(&queue_description, IID_PPV_ARGS(&queue));
    device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&allocator));
    device->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, allocator, nullptr, IID_PPV_ARGS(&list));
    list->Close();
    D3D12_DESCRIPTOR_HEAP_DESC heap_description{};
    heap_description.NumDescriptors = buffers;
    heap_description.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
    device->CreateDescriptorHeap(&heap_description, IID_PPV_ARGS(&heap));
    descriptor_size = device->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_RTV);
    device->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&fence));
    event = CreateEventW(nullptr, FALSE, FALSE, nullptr);

    auto chain = gui::d3d12::create_swap_chain(window, queue, {.buffer_count = buffers});
    if (!chain)
    {
      std::println(stderr, "swap chain: {}", chain.error().msg);
      return false;
    }
    swap_chain = static_cast<IDXGISwapChain3 *>(*chain);
    if (auto luid = gui::adapter_luid(window))
      std::println("the window's monitor is driven by the adapter with LUID {:02x}{:02x}{:02x}{:02x}..., which cuDeviceGetLuid reports for the same GPU", (*luid)[0], (*luid)[1], (*luid)[2], (*luid)[3]);
    make_targets();
    return true;
  }

  void make_targets()
  {
    auto handle = heap->GetCPUDescriptorHandleForHeapStart();
    for (UINT i = 0; i < buffers; ++i)
    {
      swap_chain->GetBuffer(i, IID_PPV_ARGS(&targets[i]));
      device->CreateRenderTargetView(targets[i], nullptr, handle);
      handle.ptr += descriptor_size;
    }
  }

  void wait()
  {
    if (!queue || !fence)
      return;
    queue->Signal(fence, ++fence_value);
    if (fence->GetCompletedValue() < fence_value)
    {
      fence->SetEventOnCompletion(fence_value, event);
      WaitForSingleObject(event, INFINITE);
    }
  }

  void resize(gui::extent_t framebuffer)
  {
    wait();
    for (auto *&target : targets)
      release(target);
    if (gui::d3d12::resize_swap_chain(swap_chain, framebuffer))
      make_targets();
  }

  static D3D12_RESOURCE_BARRIER transition(ID3D12Resource *resource, D3D12_RESOURCE_STATES from, D3D12_RESOURCE_STATES to)
  {
    D3D12_RESOURCE_BARRIER barrier{};
    barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
    barrier.Transition.pResource = resource;
    barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
    barrier.Transition.StateBefore = from;
    barrier.Transition.StateAfter = to;
    return barrier;
  }

  void clear(double time)
  {
    const UINT index = swap_chain->GetCurrentBackBufferIndex();
    allocator->Reset();
    list->Reset(allocator, nullptr);
    auto to_target = transition(targets[index], D3D12_RESOURCE_STATE_PRESENT, D3D12_RESOURCE_STATE_RENDER_TARGET);
    list->ResourceBarrier(1, &to_target);
    auto handle = heap->GetCPUDescriptorHandleForHeapStart();
    handle.ptr += static_cast<SIZE_T>(index) * descriptor_size;
    const float colour[4] = {static_cast<float>(0.5 + 0.5 * std::sin(time)), 0.4f, static_cast<float>(0.5 + 0.5 * std::cos(time)), 1.0f};
    list->ClearRenderTargetView(handle, colour, 0, nullptr);
    auto to_present = transition(targets[index], D3D12_RESOURCE_STATE_RENDER_TARGET, D3D12_RESOURCE_STATE_PRESENT);
    list->ResourceBarrier(1, &to_present);
    list->Close();
    ID3D12CommandList *lists[] = {list};
    queue->ExecuteCommandLists(1, lists);
    swap_chain->Present(1, 0);
    wait();
  }
};
} // namespace

int main(int argc, char **argv)
{
  const std::uint64_t frame_limit = argc > 1 ? std::strtoull(argv[1], nullptr, 10) : 0;
  return vio::run([frame_limit](vio::event_loop_t &loop) -> vio::task_t<int> {
    auto display = gui::display_t::open(loop);
    if (!display)
    {
      std::println(stderr, "no display: {}", display.error().msg);
      co_return 1;
    }
    int status = 0;
    {
      auto window = gui::window_t::create(*display, {.title = "direct3d 12 clear", .size = {640, 400}});
      if (!window)
        co_return 1;
      bool close = false;
      auto closing = [](gui::window_t &window, bool &close) -> vio::task_t<void> {
        if (co_await window.close_requested())
          close = true;
      }(*window, close);
      {
        renderer_t renderer;
        if (!renderer.create(*window))
        {
          std::println(stderr, "Direct3D 12 setup failed");
          status = 1;
        }
        gui::extent_t built = window->framebuffer_size();
        while (status == 0 && !close)
        {
          auto frame = co_await window->frame();
          if (!frame)
            break;
          if (frame->framebuffer != built && frame->framebuffer.width > 0 && frame->framebuffer.height > 0)
          {
            built = frame->framebuffer;
            renderer.resize(built);
          }
          renderer.clear(static_cast<double>(frame->time_ns) / 1e9);
          if (frame_limit > 0 && frame->number >= frame_limit)
            break;
        }
      }
      window->close();
      co_await std::move(closing);
    }
    co_return status;
  });
}
