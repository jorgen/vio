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

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <print>

#include <vio/gui/context.h>
#include <vio/gui/gui.h>
#include <vio/run.h>

#import <Metal/Metal.h>
#import <QuartzCore/CAMetalLayer.h>

namespace gui = vio::gui;

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
      auto window = gui::window_t::create(*display, {.title = "metal clear", .size = {640, 400}});
      if (!window)
        co_return 1;
      bool close = false;
      auto closing = [](gui::window_t &window, bool &close) -> vio::task_t<void> {
        if (co_await window.close_requested())
          close = true;
      }(*window, close);

      id<MTLDevice> device = MTLCreateSystemDefaultDevice();
      auto layer_pointer = gui::metal::create_layer(*window);
      if (!device || !layer_pointer)
      {
        std::println(stderr, "no Metal device");
        status = 1;
      }
      else
      {
        auto *layer = (__bridge CAMetalLayer *)*layer_pointer;
        layer.device = device;
        layer.pixelFormat = MTLPixelFormatBGRA8Unorm;
        id<MTLCommandQueue> queue = [device newCommandQueue];
        while (!close)
        {
          auto frame = co_await window->frame();
          if (!frame)
            break;
          @autoreleasepool
          {
            id<CAMetalDrawable> drawable = [layer nextDrawable];
            if (!drawable)
              continue;
            const double t = static_cast<double>(frame->time_ns) / 1e9;
            MTLRenderPassDescriptor *pass = [MTLRenderPassDescriptor renderPassDescriptor];
            pass.colorAttachments[0].texture = drawable.texture;
            pass.colorAttachments[0].loadAction = MTLLoadActionClear;
            pass.colorAttachments[0].storeAction = MTLStoreActionStore;
            pass.colorAttachments[0].clearColor = MTLClearColorMake(0.5 + 0.5 * std::sin(t), 0.4, 0.5 + 0.5 * std::cos(t), 1.0);
            id<MTLCommandBuffer> commands = [queue commandBuffer];
            id<MTLRenderCommandEncoder> encoder = [commands renderCommandEncoderWithDescriptor:pass];
            [encoder endEncoding];
            [commands presentDrawable:drawable];
            [commands commit];
          }
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
