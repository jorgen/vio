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

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <print>
#include <vector>

#include <vulkan/vulkan.h>

#include <vio/gui/context.h>
#include <vio/gui/gui.h>
#include <vio/run.h>

namespace gui = vio::gui;

namespace
{
struct device_t
{
  VkInstance instance = VK_NULL_HANDLE;
  VkSurfaceKHR surface = VK_NULL_HANDLE;
  VkPhysicalDevice physical = VK_NULL_HANDLE;
  std::uint32_t family = 0;
  VkDevice device = VK_NULL_HANDLE;
  VkQueue queue = VK_NULL_HANDLE;
  VkCommandPool pool = VK_NULL_HANDLE;
  VkCommandBuffer commands = VK_NULL_HANDLE;
  VkSemaphore acquired = VK_NULL_HANDLE;
  VkSemaphore rendered = VK_NULL_HANDLE;
  VkFence fence = VK_NULL_HANDLE;
  VkSwapchainKHR swapchain = VK_NULL_HANDLE;
  VkExtent2D extent{};
  std::vector<VkImage> images;

  ~device_t()
  {
    if (device)
    {
      vkDeviceWaitIdle(device);
      if (swapchain)
        vkDestroySwapchainKHR(device, swapchain, nullptr);
      vkDestroyFence(device, fence, nullptr);
      vkDestroySemaphore(device, rendered, nullptr);
      vkDestroySemaphore(device, acquired, nullptr);
      vkDestroyCommandPool(device, pool, nullptr);
      vkDestroyDevice(device, nullptr);
    }
    if (surface)
      vkDestroySurfaceKHR(instance, surface, nullptr);
    if (instance)
      vkDestroyInstance(instance, nullptr);
  }

  bool create(gui::display_t &display, gui::window_t &window)
  {
    auto extensions = gui::vulkan::required_instance_extensions(display);
    VkApplicationInfo application{VK_STRUCTURE_TYPE_APPLICATION_INFO};
    application.pApplicationName = "vulkan clear";
    application.apiVersion = VK_API_VERSION_1_1;
    VkInstanceCreateInfo instance_info{VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO};
    instance_info.pApplicationInfo = &application;
#if defined(__APPLE__)
    extensions.push_back(VK_KHR_PORTABILITY_ENUMERATION_EXTENSION_NAME);
    instance_info.flags |= VK_INSTANCE_CREATE_ENUMERATE_PORTABILITY_BIT_KHR;
#endif
    instance_info.enabledExtensionCount = static_cast<std::uint32_t>(extensions.size());
    instance_info.ppEnabledExtensionNames = extensions.data();
    if (vkCreateInstance(&instance_info, nullptr, &instance) != VK_SUCCESS)
      return false;

    auto made = gui::vulkan::create_surface(window, instance, reinterpret_cast<gui::vulkan::get_instance_proc_addr_t>(&vkGetInstanceProcAddr));
    if (!made)
    {
      std::println(stderr, "surface: {}", made.error().msg);
      return false;
    }
    surface = reinterpret_cast<VkSurfaceKHR>(*made);

    std::uint32_t count = 0;
    vkEnumeratePhysicalDevices(instance, &count, nullptr);
    std::vector<VkPhysicalDevice> devices(count);
    vkEnumeratePhysicalDevices(instance, &count, devices.data());
    for (auto candidate : devices)
    {
      std::uint32_t families = 0;
      vkGetPhysicalDeviceQueueFamilyProperties(candidate, &families, nullptr);
      std::vector<VkQueueFamilyProperties> properties(families);
      vkGetPhysicalDeviceQueueFamilyProperties(candidate, &families, properties.data());
      for (std::uint32_t i = 0; i < families && !physical; ++i)
      {
        VkBool32 present = VK_FALSE;
        vkGetPhysicalDeviceSurfaceSupportKHR(candidate, i, surface, &present);
        if (present && (properties[i].queueFlags & VK_QUEUE_GRAPHICS_BIT))
        {
          physical = candidate;
          family = i;
        }
      }
    }
    if (!physical)
      return false;
    if (auto uuid = gui::vulkan::device_uuid(instance, physical, reinterpret_cast<gui::vulkan::get_instance_proc_addr_t>(&vkGetInstanceProcAddr)))
      std::println("device uuid starts {:02x}{:02x}{:02x}{:02x}, the value cuDeviceGetUuid reports for the same GPU", (*uuid)[0], (*uuid)[1], (*uuid)[2], (*uuid)[3]);

    const float priority = 1.0f;
    VkDeviceQueueCreateInfo queue_info{VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO};
    queue_info.queueFamilyIndex = family;
    queue_info.queueCount = 1;
    queue_info.pQueuePriorities = &priority;
    std::vector<const char *> device_extensions = {VK_KHR_SWAPCHAIN_EXTENSION_NAME};
#if defined(__APPLE__)
    device_extensions.push_back("VK_KHR_portability_subset");
#endif
    VkDeviceCreateInfo device_info{VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO};
    device_info.queueCreateInfoCount = 1;
    device_info.pQueueCreateInfos = &queue_info;
    device_info.enabledExtensionCount = static_cast<std::uint32_t>(device_extensions.size());
    device_info.ppEnabledExtensionNames = device_extensions.data();
    if (vkCreateDevice(physical, &device_info, nullptr, &device) != VK_SUCCESS)
      return false;
    vkGetDeviceQueue(device, family, 0, &queue);

    VkCommandPoolCreateInfo pool_info{VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO};
    pool_info.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    pool_info.queueFamilyIndex = family;
    vkCreateCommandPool(device, &pool_info, nullptr, &pool);
    VkCommandBufferAllocateInfo allocate{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
    allocate.commandPool = pool;
    allocate.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocate.commandBufferCount = 1;
    vkAllocateCommandBuffers(device, &allocate, &commands);
    VkSemaphoreCreateInfo semaphore{VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO};
    vkCreateSemaphore(device, &semaphore, nullptr, &acquired);
    vkCreateSemaphore(device, &semaphore, nullptr, &rendered);
    VkFenceCreateInfo fence_info{VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};
    fence_info.flags = VK_FENCE_CREATE_SIGNALED_BIT;
    vkCreateFence(device, &fence_info, nullptr, &fence);
    return true;
  }

  bool build_swapchain(gui::extent_t framebuffer)
  {
    vkDeviceWaitIdle(device);
    VkSurfaceCapabilitiesKHR capabilities{};
    vkGetPhysicalDeviceSurfaceCapabilitiesKHR(physical, surface, &capabilities);
    std::uint32_t count = 0;
    vkGetPhysicalDeviceSurfaceFormatsKHR(physical, surface, &count, nullptr);
    std::vector<VkSurfaceFormatKHR> formats(count);
    vkGetPhysicalDeviceSurfaceFormatsKHR(physical, surface, &count, formats.data());
    if (formats.empty())
      return false;
    extent = capabilities.currentExtent;
    if (extent.width == UINT32_MAX)
    {
      extent.width = std::clamp(static_cast<std::uint32_t>(framebuffer.width), capabilities.minImageExtent.width, capabilities.maxImageExtent.width);
      extent.height = std::clamp(static_cast<std::uint32_t>(framebuffer.height), capabilities.minImageExtent.height, capabilities.maxImageExtent.height);
    }
    VkSwapchainCreateInfoKHR info{VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR};
    info.surface = surface;
    info.minImageCount = std::max(2u, capabilities.minImageCount);
    if (capabilities.maxImageCount > 0)
      info.minImageCount = std::min(info.minImageCount, capabilities.maxImageCount);
    info.imageFormat = formats[0].format;
    info.imageColorSpace = formats[0].colorSpace;
    info.imageExtent = extent;
    info.imageArrayLayers = 1;
    info.imageUsage = VK_IMAGE_USAGE_TRANSFER_DST_BIT;
    info.imageSharingMode = VK_SHARING_MODE_EXCLUSIVE;
    info.preTransform = capabilities.currentTransform;
    info.compositeAlpha = VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR;
    info.presentMode = VK_PRESENT_MODE_FIFO_KHR;
    info.clipped = VK_TRUE;
    info.oldSwapchain = swapchain;
    VkSwapchainKHR replacement = VK_NULL_HANDLE;
    if (vkCreateSwapchainKHR(device, &info, nullptr, &replacement) != VK_SUCCESS)
      return false;
    if (swapchain)
      vkDestroySwapchainKHR(device, swapchain, nullptr);
    swapchain = replacement;
    vkGetSwapchainImagesKHR(device, swapchain, &count, nullptr);
    images.resize(count);
    vkGetSwapchainImagesKHR(device, swapchain, &count, images.data());
    return true;
  }

  static void barrier(VkCommandBuffer commands, VkImage image, VkImageLayout from, VkImageLayout to)
  {
    VkImageMemoryBarrier barrier{VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER};
    barrier.oldLayout = from;
    barrier.newLayout = to;
    barrier.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    barrier.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    barrier.image = image;
    barrier.subresourceRange = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1};
    barrier.dstAccessMask = to == VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL ? VK_ACCESS_TRANSFER_WRITE_BIT : 0;
    barrier.srcAccessMask = from == VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL ? VK_ACCESS_TRANSFER_WRITE_BIT : 0;
    vkCmdPipelineBarrier(commands, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT, 0, 0, nullptr, 0, nullptr, 1, &barrier);
  }

  VkResult clear(float time)
  {
    vkWaitForFences(device, 1, &fence, VK_TRUE, UINT64_MAX);
    std::uint32_t index = 0;
    VkResult result = vkAcquireNextImageKHR(device, swapchain, UINT64_MAX, acquired, VK_NULL_HANDLE, &index);
    if (result != VK_SUCCESS && result != VK_SUBOPTIMAL_KHR)
      return result;
    vkResetFences(device, 1, &fence);
    vkResetCommandBuffer(commands, 0);
    VkCommandBufferBeginInfo begin{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    begin.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(commands, &begin);
    barrier(commands, images[index], VK_IMAGE_LAYOUT_UNDEFINED, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL);
    VkClearColorValue colour{{0.5f + 0.5f * std::sin(time), 0.4f, 0.5f + 0.5f * std::cos(time), 1.0f}};
    VkImageSubresourceRange range{VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1};
    vkCmdClearColorImage(commands, images[index], VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, &colour, 1, &range);
    barrier(commands, images[index], VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, VK_IMAGE_LAYOUT_PRESENT_SRC_KHR);
    vkEndCommandBuffer(commands);

    const VkPipelineStageFlags wait_stage = VK_PIPELINE_STAGE_TRANSFER_BIT;
    VkSubmitInfo submit{VK_STRUCTURE_TYPE_SUBMIT_INFO};
    submit.waitSemaphoreCount = 1;
    submit.pWaitSemaphores = &acquired;
    submit.pWaitDstStageMask = &wait_stage;
    submit.commandBufferCount = 1;
    submit.pCommandBuffers = &commands;
    submit.signalSemaphoreCount = 1;
    submit.pSignalSemaphores = &rendered;
    vkQueueSubmit(queue, 1, &submit, fence);

    VkPresentInfoKHR present{VK_STRUCTURE_TYPE_PRESENT_INFO_KHR};
    present.waitSemaphoreCount = 1;
    present.pWaitSemaphores = &rendered;
    present.swapchainCount = 1;
    present.pSwapchains = &swapchain;
    present.pImageIndices = &index;
    return vkQueuePresentKHR(queue, &present);
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
      auto window = gui::window_t::create(*display, {.title = "vulkan clear", .size = {640, 400}});
      if (!window)
        co_return 1;
      bool close = false;
      auto closing = [](gui::window_t &window, bool &close) -> vio::task_t<void> {
        if (co_await window.close_requested())
          close = true;
      }(*window, close);
      {
        device_t vulkan;
        if (!vulkan.create(*display, *window) || !vulkan.build_swapchain(window->framebuffer_size()))
        {
          std::println(stderr, "Vulkan setup failed");
          status = 1;
        }
        gui::extent_t built = window->framebuffer_size();
        while (status == 0 && !close)
        {
          auto frame = co_await window->frame();
          if (!frame)
            break;
          if (frame->framebuffer != built)
          {
            built = frame->framebuffer;
            vulkan.build_swapchain(built);
          }
          const VkResult result = vulkan.clear(static_cast<float>(frame->time_ns) / 1e9f);
          if (result == VK_ERROR_OUT_OF_DATE_KHR || result == VK_SUBOPTIMAL_KHR)
            vulkan.build_swapchain(built);
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
