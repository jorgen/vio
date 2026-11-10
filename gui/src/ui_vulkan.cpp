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

// The Vulkan renderer (G30, G31). The loader is opened at run time (G6) and every entry point is
// fetched through vkGetInstanceProcAddr / vkGetDeviceProcAddr, so nothing is linked and a machine
// without Vulkan falls back to the GL stopgap. Vulkan 1.0 with a classic render pass: the most
// widely available shape, and everything this pipeline needs.

#define VK_NO_PROTOTYPES
#include <vulkan/vulkan.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include "shaders/ui_spirv.h"
#include "ui_renderer.h"
#include "vio/gui/context.h"

namespace vio::gui::ui::detail
{
namespace
{
// ---- the loader, opened once and never closed, as EGL is (G11).
PFN_vkGetInstanceProcAddr load_loader()
{
  static PFN_vkGetInstanceProcAddr get = []() -> PFN_vkGetInstanceProcAddr
  {
#if defined(_WIN32)
    HMODULE library = LoadLibraryW(L"vulkan-1.dll");
    if (!library)
      return nullptr;
    return reinterpret_cast<PFN_vkGetInstanceProcAddr>(reinterpret_cast<void *>(GetProcAddress(library, "vkGetInstanceProcAddr")));
#else
#if defined(__APPLE__)
    const char *names[] = {"libvulkan.1.dylib", "libvulkan.dylib", "libMoltenVK.dylib"};
#else
    const char *names[] = {"libvulkan.so.1", "libvulkan.so"};
#endif
    for (const char *name : names)
    {
      if (void *library = dlopen(name, RTLD_NOW | RTLD_LOCAL))
        return reinterpret_cast<PFN_vkGetInstanceProcAddr>(dlsym(library, "vkGetInstanceProcAddr"));
    }
    return nullptr;
#endif
  }();
  return get;
}

#define VIO_VK_INSTANCE_FUNCTIONS(X)                                                                                                                                                                                       \
  X(vkDestroyInstance)                                                                                                                                                                                                     \
  X(vkEnumeratePhysicalDevices)                                                                                                                                                                                            \
  X(vkGetPhysicalDeviceProperties)                                                                                                                                                                                         \
  X(vkGetPhysicalDeviceQueueFamilyProperties)                                                                                                                                                                              \
  X(vkGetPhysicalDeviceMemoryProperties)                                                                                                                                                                                   \
  X(vkEnumerateDeviceExtensionProperties)                                                                                                                                                                                  \
  X(vkCreateDevice)                                                                                                                                                                                                        \
  X(vkGetDeviceProcAddr)

#define VIO_VK_SURFACE_FUNCTIONS(X)                                                                                                                                                                                        \
  X(vkDestroySurfaceKHR)                                                                                                                                                                                                   \
  X(vkGetPhysicalDeviceSurfaceSupportKHR)                                                                                                                                                                                  \
  X(vkGetPhysicalDeviceSurfaceCapabilitiesKHR)                                                                                                                                                                             \
  X(vkGetPhysicalDeviceSurfaceFormatsKHR)

#define VIO_VK_DEVICE_FUNCTIONS(X)                                                                                                                                                                                         \
  X(vkDestroyDevice)                                                                                                                                                                                                       \
  X(vkGetDeviceQueue)                                                                                                                                                                                                      \
  X(vkDeviceWaitIdle)                                                                                                                                                                                                      \
  X(vkCreateImageView)                                                                                                                                                                                                     \
  X(vkDestroyImageView)                                                                                                                                                                                                    \
  X(vkCreateRenderPass)                                                                                                                                                                                                    \
  X(vkDestroyRenderPass)                                                                                                                                                                                                   \
  X(vkCreateFramebuffer)                                                                                                                                                                                                   \
  X(vkDestroyFramebuffer)                                                                                                                                                                                                  \
  X(vkCreateShaderModule)                                                                                                                                                                                                  \
  X(vkDestroyShaderModule)                                                                                                                                                                                                 \
  X(vkCreatePipelineLayout)                                                                                                                                                                                                \
  X(vkDestroyPipelineLayout)                                                                                                                                                                                               \
  X(vkCreateGraphicsPipelines)                                                                                                                                                                                             \
  X(vkDestroyPipeline)                                                                                                                                                                                                     \
  X(vkCreateCommandPool)                                                                                                                                                                                                   \
  X(vkDestroyCommandPool)                                                                                                                                                                                                  \
  X(vkAllocateCommandBuffers)                                                                                                                                                                                              \
  X(vkBeginCommandBuffer)                                                                                                                                                                                                  \
  X(vkEndCommandBuffer)                                                                                                                                                                                                    \
  X(vkCmdBeginRenderPass)                                                                                                                                                                                                  \
  X(vkCmdEndRenderPass)                                                                                                                                                                                                    \
  X(vkCmdBindPipeline)                                                                                                                                                                                                     \
  X(vkCmdBindVertexBuffers)                                                                                                                                                                                                \
  X(vkCmdSetViewport)                                                                                                                                                                                                      \
  X(vkCmdSetScissor)                                                                                                                                                                                                       \
  X(vkCmdPushConstants)                                                                                                                                                                                                    \
  X(vkCmdDraw)                                                                                                                                                                                                             \
  X(vkCmdCopyImageToBuffer)                                                                                                                                                                                                \
  X(vkCmdPipelineBarrier) X(vkCreateSemaphore) X(vkDestroySemaphore) X(vkCreateFence) X(vkDestroyFence) X(vkWaitForFences) X(vkResetFences) X(vkQueueSubmit) X(vkQueueWaitIdle) X(vkCreateBuffer) X(vkDestroyBuffer)       \
    X(vkGetBufferMemoryRequirements) X(vkBindBufferMemory) X(vkCreateImage) X(vkDestroyImage) X(vkGetImageMemoryRequirements) X(vkBindImageMemory) X(vkAllocateMemory) X(vkFreeMemory) X(vkMapMemory) X(vkUnmapMemory)

#define VIO_VK_SWAPCHAIN_FUNCTIONS(X)                                                                                                                                                                                      \
  X(vkCreateSwapchainKHR)                                                                                                                                                                                                  \
  X(vkDestroySwapchainKHR)                                                                                                                                                                                                 \
  X(vkGetSwapchainImagesKHR)                                                                                                                                                                                               \
  X(vkAcquireNextImageKHR)                                                                                                                                                                                                 \
  X(vkQueuePresentKHR)

#define VIO_VK_DECLARE(name) PFN_##name name = nullptr;

// One device, created here or borrowed from the program (G31), with the entry points the renderer
// uses. A borrowed device is never destroyed here; only what this file created is.
struct device_t
{
  PFN_vkGetInstanceProcAddr get_instance = nullptr;
  VkInstance instance = VK_NULL_HANDLE;
  VkPhysicalDevice physical = VK_NULL_HANDLE;
  VkDevice device = VK_NULL_HANDLE;
  VkQueue queue = VK_NULL_HANDLE;
  std::uint32_t family = 0;
  bool owned = false;
  bool presents = false;
  VkPhysicalDeviceMemoryProperties memory{};
  std::string name;

  VIO_VK_INSTANCE_FUNCTIONS(VIO_VK_DECLARE)
  VIO_VK_SURFACE_FUNCTIONS(VIO_VK_DECLARE)
  VIO_VK_DEVICE_FUNCTIONS(VIO_VK_DECLARE)
  VIO_VK_SWAPCHAIN_FUNCTIONS(VIO_VK_DECLARE)

  device_t() = default;
  device_t(const device_t &) = delete;
  device_t &operator=(const device_t &) = delete;
  ~device_t()
  {
    if (!owned)
      return;
    if (device && vkDestroyDevice)
    {
      vkDeviceWaitIdle(device);
      vkDestroyDevice(device, nullptr);
    }
    if (instance && vkDestroyInstance)
      vkDestroyInstance(instance, nullptr);
  }

  bool load_instance(std::string &why)
  {
#define VIO_VK_LOAD_INSTANCE(name)                                                                                                                                                                                         \
  name = reinterpret_cast<PFN_##name>(get_instance(instance, #name));                                                                                                                                                      \
  if (!name)                                                                                                                                                                                                               \
  {                                                                                                                                                                                                                        \
    why = "missing " #name;                                                                                                                                                                                                \
    return false;                                                                                                                                                                                                          \
  }
    VIO_VK_INSTANCE_FUNCTIONS(VIO_VK_LOAD_INSTANCE)
    if (presents)
    {
      VIO_VK_SURFACE_FUNCTIONS(VIO_VK_LOAD_INSTANCE)
    }
#undef VIO_VK_LOAD_INSTANCE
    return true;
  }

  bool load_device(std::string &why)
  {
#define VIO_VK_LOAD_DEVICE(name)                                                                                                                                                                                           \
  name = reinterpret_cast<PFN_##name>(vkGetDeviceProcAddr(device, #name));                                                                                                                                                 \
  if (!name)                                                                                                                                                                                                               \
  {                                                                                                                                                                                                                        \
    why = "missing " #name;                                                                                                                                                                                                \
    return false;                                                                                                                                                                                                          \
  }
    VIO_VK_DEVICE_FUNCTIONS(VIO_VK_LOAD_DEVICE)
    if (presents)
    {
      VIO_VK_SWAPCHAIN_FUNCTIONS(VIO_VK_LOAD_DEVICE)
    }
#undef VIO_VK_LOAD_DEVICE
    return true;
  }

  [[nodiscard]] std::optional<std::uint32_t> memory_type(std::uint32_t bits, VkMemoryPropertyFlags wanted) const noexcept
  {
    for (std::uint32_t i = 0; i < memory.memoryTypeCount; ++i)
    {
      if ((bits & (1u << i)) && (memory.memoryTypes[i].propertyFlags & wanted) == wanted)
        return i;
    }
    return std::nullopt;
  }
};

bool has_extension(std::span<const VkExtensionProperties> available, const char *name)
{
  return std::any_of(available.begin(), available.end(), [name](const VkExtensionProperties &p) { return std::strcmp(p.extensionName, name) == 0; });
}

bool env_flag(const char *name)
{
#if defined(_MSC_VER)
  char *value = nullptr;
  std::size_t size = 0;
  if (_dupenv_s(&value, &size, name) != 0 || !value)
    return false;
  const bool on = value[0] == '1';
  std::free(value);
  return on;
#else
  const char *value = std::getenv(name);
  return value && value[0] == '1';
#endif
}

// Create an instance of our own. `surface_extensions` is empty for an offscreen device.
bool create_instance(device_t &d, std::span<const char *const> surface_extensions, std::string &why)
{
  d.get_instance = load_loader();
  if (!d.get_instance)
  {
    why = "no Vulkan loader";
    return false;
  }
  auto create = reinterpret_cast<PFN_vkCreateInstance>(d.get_instance(VK_NULL_HANDLE, "vkCreateInstance"));
  auto enumerate = reinterpret_cast<PFN_vkEnumerateInstanceExtensionProperties>(d.get_instance(VK_NULL_HANDLE, "vkEnumerateInstanceExtensionProperties"));
  auto layers = reinterpret_cast<PFN_vkEnumerateInstanceLayerProperties>(d.get_instance(VK_NULL_HANDLE, "vkEnumerateInstanceLayerProperties"));
  if (!create || !enumerate)
  {
    why = "the Vulkan loader has no vkCreateInstance";
    return false;
  }
  std::uint32_t count = 0;
  enumerate(nullptr, &count, nullptr);
  std::vector<VkExtensionProperties> available(count);
  enumerate(nullptr, &count, available.data());

  std::vector<const char *> extensions;
  for (const char *name : surface_extensions)
  {
    if (!has_extension(available, name))
    {
      why = std::string("instance extension missing: ") + name;
      return false;
    }
    extensions.push_back(name);
  }
  VkInstanceCreateInfo info{VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO};
  // MoltenVK is a portability implementation and is enumerated only when asked for.
  if (has_extension(available, VK_KHR_PORTABILITY_ENUMERATION_EXTENSION_NAME))
  {
    extensions.push_back(VK_KHR_PORTABILITY_ENUMERATION_EXTENSION_NAME);
    info.flags |= VK_INSTANCE_CREATE_ENUMERATE_PORTABILITY_BIT_KHR;
  }
  const char *validation = "VK_LAYER_KHRONOS_validation";
  bool validate = false;
  if (env_flag("VIO_VULKAN_VALIDATION") && layers)
  {
    std::uint32_t layer_count = 0;
    layers(&layer_count, nullptr);
    std::vector<VkLayerProperties> layer_list(layer_count);
    layers(&layer_count, layer_list.data());
    validate = std::any_of(layer_list.begin(), layer_list.end(), [&](const VkLayerProperties &p) { return std::strcmp(p.layerName, validation) == 0; });
  }
  VkApplicationInfo application{VK_STRUCTURE_TYPE_APPLICATION_INFO};
  application.pApplicationName = "vio gui";
  application.pEngineName = "vio gui ui";
  application.apiVersion = VK_API_VERSION_1_0;
  info.pApplicationInfo = &application;
  info.enabledExtensionCount = std::uint32_t(extensions.size());
  info.ppEnabledExtensionNames = extensions.data();
  info.enabledLayerCount = validate ? 1 : 0;
  info.ppEnabledLayerNames = validate ? &validation : nullptr;
  if (create(&info, nullptr, &d.instance) != VK_SUCCESS)
  {
    why = "vkCreateInstance failed";
    return false;
  }
  d.owned = true;
  d.presents = !surface_extensions.empty();
  return d.load_instance(why);
}

// Pick a device and a queue family that draws and, when `surface` is given, presents to it.
// Discrete GPUs first, then integrated, then anything else -- lavapipe last.
bool create_device(device_t &d, VkSurfaceKHR surface, std::string &why)
{
  std::uint32_t count = 0;
  d.vkEnumeratePhysicalDevices(d.instance, &count, nullptr);
  std::vector<VkPhysicalDevice> devices(count);
  d.vkEnumeratePhysicalDevices(d.instance, &count, devices.data());
  auto rank = [&](VkPhysicalDevice device)
  {
    VkPhysicalDeviceProperties properties;
    d.vkGetPhysicalDeviceProperties(device, &properties);
    switch (properties.deviceType)
    {
    case VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU:
      return 0;
    case VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU:
      return 1;
    case VK_PHYSICAL_DEVICE_TYPE_VIRTUAL_GPU:
      return 2;
    default:
      return 3;
    }
  };
  std::stable_sort(devices.begin(), devices.end(), [&](VkPhysicalDevice a, VkPhysicalDevice b) { return rank(a) < rank(b); });
  for (auto candidate : devices)
  {
    std::uint32_t families = 0;
    d.vkGetPhysicalDeviceQueueFamilyProperties(candidate, &families, nullptr);
    std::vector<VkQueueFamilyProperties> properties(families);
    d.vkGetPhysicalDeviceQueueFamilyProperties(candidate, &families, properties.data());
    for (std::uint32_t i = 0; i < families; ++i)
    {
      if (!(properties[i].queueFlags & VK_QUEUE_GRAPHICS_BIT))
        continue;
      if (surface)
      {
        VkBool32 present = VK_FALSE;
        d.vkGetPhysicalDeviceSurfaceSupportKHR(candidate, i, surface, &present);
        if (!present)
          continue;
      }
      d.physical = candidate;
      d.family = i;
      break;
    }
    if (d.physical)
      break;
  }
  if (!d.physical)
  {
    why = surface ? "no Vulkan device can present to this window" : "no Vulkan device draws";
    return false;
  }

  std::uint32_t extension_count = 0;
  d.vkEnumerateDeviceExtensionProperties(d.physical, nullptr, &extension_count, nullptr);
  std::vector<VkExtensionProperties> available(extension_count);
  d.vkEnumerateDeviceExtensionProperties(d.physical, nullptr, &extension_count, available.data());
  std::vector<const char *> extensions;
  if (surface)
  {
    if (!has_extension(available, VK_KHR_SWAPCHAIN_EXTENSION_NAME))
    {
      why = "the Vulkan device has no VK_KHR_swapchain";
      return false;
    }
    extensions.push_back(VK_KHR_SWAPCHAIN_EXTENSION_NAME);
  }
  if (has_extension(available, "VK_KHR_portability_subset"))
    extensions.push_back("VK_KHR_portability_subset");

  const float priority = 1.0f;
  VkDeviceQueueCreateInfo queue_info{VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO};
  queue_info.queueFamilyIndex = d.family;
  queue_info.queueCount = 1;
  queue_info.pQueuePriorities = &priority;
  VkDeviceCreateInfo info{VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO};
  info.queueCreateInfoCount = 1;
  info.pQueueCreateInfos = &queue_info;
  info.enabledExtensionCount = std::uint32_t(extensions.size());
  info.ppEnabledExtensionNames = extensions.data();
  if (d.vkCreateDevice(d.physical, &info, nullptr, &d.device) != VK_SUCCESS)
  {
    why = "vkCreateDevice failed";
    return false;
  }
  if (!d.load_device(why))
    return false;
  d.vkGetDeviceQueue(d.device, d.family, 0, &d.queue);
  return true;
}

void finish_device(device_t &d)
{
  d.vkGetPhysicalDeviceMemoryProperties(d.physical, &d.memory);
  VkPhysicalDeviceProperties properties;
  d.vkGetPhysicalDeviceProperties(d.physical, &properties);
  d.name = properties.deviceName;
}

// Borrow the program's device (G31): its instance, device and queue, our own everything else.
bool borrow_device(device_t &d, const vulkan_device_t &shared, std::string &why)
{
  if (!shared.instance || !shared.physical_device || !shared.device || !shared.queue || !shared.get_instance_proc_addr)
  {
    why = "vulkan_device_t is incomplete";
    return false;
  }
  d.get_instance = reinterpret_cast<PFN_vkGetInstanceProcAddr>(shared.get_instance_proc_addr);
  d.instance = static_cast<VkInstance>(shared.instance);
  d.physical = static_cast<VkPhysicalDevice>(shared.physical_device);
  d.device = static_cast<VkDevice>(shared.device);
  d.queue = static_cast<VkQueue>(shared.queue);
  d.family = shared.queue_family;
  d.owned = false;
  d.presents = true;
  return d.load_instance(why) && d.load_device(why);
}

// ---- the pipeline: one render pass, one pipeline, the vertex buffer of prims read per instance.
struct push_t
{
  float origin[2];
  float scale[2];
  float target[2];
  float encode_srgb;
  float pad;
};
static_assert(sizeof(push_t) == 32);

float to_linear(float c)
{
  return c <= 0.04045f ? c / 12.92f : std::pow((c + 0.055f) / 1.055f, 2.4f);
}

struct buffer_t
{
  VkBuffer buffer = VK_NULL_HANDLE;
  VkDeviceMemory memory = VK_NULL_HANDLE;
  void *mapped = nullptr;
  VkDeviceSize capacity = 0;
};

void release(device_t &d, buffer_t &buffer)
{
  if (buffer.mapped)
    d.vkUnmapMemory(d.device, buffer.memory);
  if (buffer.buffer)
    d.vkDestroyBuffer(d.device, buffer.buffer, nullptr);
  if (buffer.memory)
    d.vkFreeMemory(d.device, buffer.memory, nullptr);
  buffer = {};
}

// A host-visible, coherent buffer, mapped for as long as it lives.
bool make_buffer(device_t &d, buffer_t &buffer, VkDeviceSize size, VkBufferUsageFlags usage)
{
  VkBufferCreateInfo info{VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO};
  info.size = size;
  info.usage = usage;
  info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
  if (d.vkCreateBuffer(d.device, &info, nullptr, &buffer.buffer) != VK_SUCCESS)
    return false;
  VkMemoryRequirements requirements;
  d.vkGetBufferMemoryRequirements(d.device, buffer.buffer, &requirements);
  auto type = d.memory_type(requirements.memoryTypeBits, VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
  VkMemoryAllocateInfo allocate{VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO};
  allocate.allocationSize = requirements.size;
  allocate.memoryTypeIndex = type.value_or(0);
  if (!type || d.vkAllocateMemory(d.device, &allocate, nullptr, &buffer.memory) != VK_SUCCESS)
  {
    release(d, buffer);
    return false;
  }
  d.vkBindBufferMemory(d.device, buffer.buffer, buffer.memory, 0);
  if (d.vkMapMemory(d.device, buffer.memory, 0, VK_WHOLE_SIZE, 0, &buffer.mapped) != VK_SUCCESS)
  {
    release(d, buffer);
    return false;
  }
  buffer.capacity = size;
  return true;
}

class pipeline_t
{
public:
  explicit pipeline_t(device_t &d)
    : _d(d)
  {
  }
  pipeline_t(const pipeline_t &) = delete;
  pipeline_t &operator=(const pipeline_t &) = delete;
  ~pipeline_t()
  {
    if (_pipeline)
      _d.vkDestroyPipeline(_d.device, _pipeline, nullptr);
    if (_layout)
      _d.vkDestroyPipelineLayout(_d.device, _layout, nullptr);
    if (_pass)
      _d.vkDestroyRenderPass(_d.device, _pass, nullptr);
  }

  bool create(VkFormat format, VkImageLayout final_layout, std::string &why)
  {
    VkAttachmentDescription attachment{};
    attachment.format = format;
    attachment.samples = VK_SAMPLE_COUNT_1_BIT;
    attachment.loadOp = VK_ATTACHMENT_LOAD_OP_CLEAR;
    attachment.storeOp = VK_ATTACHMENT_STORE_OP_STORE;
    attachment.stencilLoadOp = VK_ATTACHMENT_LOAD_OP_DONT_CARE;
    attachment.stencilStoreOp = VK_ATTACHMENT_STORE_OP_DONT_CARE;
    attachment.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    attachment.finalLayout = final_layout;
    VkAttachmentReference reference{0, VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL};
    VkSubpassDescription subpass{};
    subpass.pipelineBindPoint = VK_PIPELINE_BIND_POINT_GRAPHICS;
    subpass.colorAttachmentCount = 1;
    subpass.pColorAttachments = &reference;
    // The acquire semaphore is waited at colour output; the image's layout transition must wait too.
    VkSubpassDependency dependency{};
    dependency.srcSubpass = VK_SUBPASS_EXTERNAL;
    dependency.dstSubpass = 0;
    dependency.srcStageMask = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    dependency.dstStageMask = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    dependency.dstAccessMask = VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT;
    VkRenderPassCreateInfo pass_info{VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO};
    pass_info.attachmentCount = 1;
    pass_info.pAttachments = &attachment;
    pass_info.subpassCount = 1;
    pass_info.pSubpasses = &subpass;
    pass_info.dependencyCount = 1;
    pass_info.pDependencies = &dependency;
    if (_d.vkCreateRenderPass(_d.device, &pass_info, nullptr, &_pass) != VK_SUCCESS)
    {
      why = "vkCreateRenderPass failed";
      return false;
    }

    VkPushConstantRange range{VK_SHADER_STAGE_VERTEX_BIT | VK_SHADER_STAGE_FRAGMENT_BIT, 0, sizeof(push_t)};
    VkPipelineLayoutCreateInfo layout_info{VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO};
    layout_info.pushConstantRangeCount = 1;
    layout_info.pPushConstantRanges = &range;
    if (_d.vkCreatePipelineLayout(_d.device, &layout_info, nullptr, &_layout) != VK_SUCCESS)
    {
      why = "vkCreatePipelineLayout failed";
      return false;
    }

    auto module = [&](std::span<const std::uint32_t> code)
    {
      VkShaderModuleCreateInfo info{VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO};
      info.codeSize = code.size_bytes();
      info.pCode = code.data();
      VkShaderModule made = VK_NULL_HANDLE;
      _d.vkCreateShaderModule(_d.device, &info, nullptr, &made);
      return made;
    };
    VkShaderModule vertex = module(shaders::ui_vertex);
    VkShaderModule fragment = module(shaders::ui_fragment);
    const std::string vertex_entry = entry_point(shaders::ui_vertex);
    const std::string fragment_entry = entry_point(shaders::ui_fragment);
    bool ok = vertex && fragment;
    if (ok)
    {
      VkPipelineShaderStageCreateInfo stages[2]{};
      stages[0].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
      stages[0].stage = VK_SHADER_STAGE_VERTEX_BIT;
      stages[0].module = vertex;
      stages[0].pName = vertex_entry.c_str();
      stages[1].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
      stages[1].stage = VK_SHADER_STAGE_FRAGMENT_BIT;
      stages[1].module = fragment;
      stages[1].pName = fragment_entry.c_str();

      VkVertexInputBindingDescription binding{0, sizeof(prim_t), VK_VERTEX_INPUT_RATE_INSTANCE};
      const VkVertexInputAttributeDescription attributes[] = {
        {0, 0, VK_FORMAT_R32G32B32A32_SFLOAT, offsetof(prim_t, x)},      {1, 0, VK_FORMAT_R32G32B32A32_SFLOAT, offsetof(prim_t, radii)},
        {2, 0, VK_FORMAT_R32G32B32A32_SFLOAT, offsetof(prim_t, fill)},   {3, 0, VK_FORMAT_R32G32B32A32_SFLOAT, offsetof(prim_t, border_color)},
        {4, 0, VK_FORMAT_R32G32_SFLOAT, offsetof(prim_t, border_width)},
      };
      VkPipelineVertexInputStateCreateInfo input{VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO};
      input.vertexBindingDescriptionCount = 1;
      input.pVertexBindingDescriptions = &binding;
      input.vertexAttributeDescriptionCount = std::uint32_t(std::size(attributes));
      input.pVertexAttributeDescriptions = attributes;
      VkPipelineInputAssemblyStateCreateInfo assembly{VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO};
      assembly.topology = VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST;
      VkPipelineViewportStateCreateInfo viewport{VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO};
      viewport.viewportCount = 1;
      viewport.scissorCount = 1;
      VkPipelineRasterizationStateCreateInfo raster{VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO};
      raster.polygonMode = VK_POLYGON_MODE_FILL;
      raster.cullMode = VK_CULL_MODE_NONE;
      raster.frontFace = VK_FRONT_FACE_COUNTER_CLOCKWISE;
      raster.lineWidth = 1.0f;
      VkPipelineMultisampleStateCreateInfo multisample{VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO};
      multisample.rasterizationSamples = VK_SAMPLE_COUNT_1_BIT;
      // Premultiplied alpha: the shader multiplies, the blender only composites.
      VkPipelineColorBlendAttachmentState blend{};
      blend.blendEnable = VK_TRUE;
      blend.srcColorBlendFactor = VK_BLEND_FACTOR_ONE;
      blend.dstColorBlendFactor = VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA;
      blend.colorBlendOp = VK_BLEND_OP_ADD;
      blend.srcAlphaBlendFactor = VK_BLEND_FACTOR_ONE;
      blend.dstAlphaBlendFactor = VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA;
      blend.alphaBlendOp = VK_BLEND_OP_ADD;
      blend.colorWriteMask = VK_COLOR_COMPONENT_R_BIT | VK_COLOR_COMPONENT_G_BIT | VK_COLOR_COMPONENT_B_BIT | VK_COLOR_COMPONENT_A_BIT;
      VkPipelineColorBlendStateCreateInfo blending{VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO};
      blending.attachmentCount = 1;
      blending.pAttachments = &blend;
      const VkDynamicState dynamic_states[] = {VK_DYNAMIC_STATE_VIEWPORT, VK_DYNAMIC_STATE_SCISSOR};
      VkPipelineDynamicStateCreateInfo dynamic{VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO};
      dynamic.dynamicStateCount = 2;
      dynamic.pDynamicStates = dynamic_states;

      VkGraphicsPipelineCreateInfo info{VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO};
      info.stageCount = 2;
      info.pStages = stages;
      info.pVertexInputState = &input;
      info.pInputAssemblyState = &assembly;
      info.pViewportState = &viewport;
      info.pRasterizationState = &raster;
      info.pMultisampleState = &multisample;
      info.pColorBlendState = &blending;
      info.pDynamicState = &dynamic;
      info.layout = _layout;
      info.renderPass = _pass;
      ok = _d.vkCreateGraphicsPipelines(_d.device, VK_NULL_HANDLE, 1, &info, nullptr, &_pipeline) == VK_SUCCESS;
    }
    if (vertex)
      _d.vkDestroyShaderModule(_d.device, vertex, nullptr);
    if (fragment)
      _d.vkDestroyShaderModule(_d.device, fragment, nullptr);
    if (!ok)
      why = "the UI pipeline did not build";
    _format = format;
    return ok;
  }

  // Grow `buffer` to hold `prims` and copy them in. The buffer is host-visible and coherent and
  // stays mapped; one per frame in flight, so nothing the GPU still reads is overwritten.
  bool upload(buffer_t &buffer, std::span<const prim_t> prims)
  {
    const VkDeviceSize needed = std::max<VkDeviceSize>(prims.size_bytes(), sizeof(prim_t));
    if (buffer.capacity < needed)
    {
      release(_d, buffer);
      VkDeviceSize capacity = 64 * sizeof(prim_t);
      while (capacity < needed)
        capacity *= 2;
      if (!make_buffer(_d, buffer, capacity, VK_BUFFER_USAGE_VERTEX_BUFFER_BIT))
        return false;
    }
    if (!prims.empty())
      std::memcpy(buffer.mapped, prims.data(), prims.size_bytes());
    return true;
  }

  // Record one frame: clear, then one instanced draw per run with the run's origin pushed.
  void record(VkCommandBuffer cmd, VkFramebuffer framebuffer, VkExtent2D extent, const buffer_t &prims, const display_list_t &list, bool encode_srgb)
  {
    const auto &bg = list.background;
    VkClearValue clear{};
    if (encode_srgb)
      clear.color = {{bg.r, bg.g, bg.b, bg.a}};
    else
      clear.color = {{to_linear(bg.r), to_linear(bg.g), to_linear(bg.b), bg.a}};
    VkRenderPassBeginInfo begin{VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO};
    begin.renderPass = _pass;
    begin.framebuffer = framebuffer;
    begin.renderArea.extent = extent;
    begin.clearValueCount = 1;
    begin.pClearValues = &clear;
    _d.vkCmdBeginRenderPass(cmd, &begin, VK_SUBPASS_CONTENTS_INLINE);
    if (!list.runs.empty())
    {
      _d.vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_GRAPHICS, _pipeline);
      VkViewport viewport{0, 0, float(extent.width), float(extent.height), 0, 1};
      VkRect2D scissor{{0, 0}, extent};
      _d.vkCmdSetViewport(cmd, 0, 1, &viewport);
      _d.vkCmdSetScissor(cmd, 0, 1, &scissor);
      VkDeviceSize offset = 0;
      _d.vkCmdBindVertexBuffers(cmd, 0, 1, &prims.buffer, &offset);
      push_t push{};
      push.scale[0] = list.logical.width > 0 ? float(extent.width) / float(list.logical.width) : list.scale;
      push.scale[1] = list.logical.height > 0 ? float(extent.height) / float(list.logical.height) : list.scale;
      push.target[0] = float(extent.width);
      push.target[1] = float(extent.height);
      push.encode_srgb = encode_srgb ? 1.0f : 0.0f;
      const auto stages = VK_SHADER_STAGE_VERTEX_BIT | VK_SHADER_STAGE_FRAGMENT_BIT;
      _d.vkCmdPushConstants(cmd, _layout, stages, 0, sizeof(push), &push);
      for (const auto &run : list.runs)
      {
        const float origin[2] = {run.x, run.y};
        _d.vkCmdPushConstants(cmd, _layout, stages, 0, sizeof(origin), origin);
        _d.vkCmdDraw(cmd, 6, run.count, 0, run.first);
      }
    }
    _d.vkCmdEndRenderPass(cmd);
  }

  [[nodiscard]] VkRenderPass pass() const noexcept
  {
    return _pass;
  }
  [[nodiscard]] VkFormat format() const noexcept
  {
    return _format;
  }

private:
  // The name in the module's first OpEntryPoint: glslang writes "main", slangc may keep the
  // function's own name, and reading it means neither has to be configured to match.
  static std::string entry_point(std::span<const std::uint32_t> code)
  {
    std::size_t i = 5;
    while (i < code.size())
    {
      const std::uint32_t count = code[i] >> 16;
      const std::uint32_t opcode = code[i] & 0xffff;
      if (count == 0)
        break;
      if (opcode == 15 && count > 3)
        return std::string(reinterpret_cast<const char *>(&code[i + 3]));
      i += count;
    }
    return "main";
  }

  device_t &_d;
  VkRenderPass _pass = VK_NULL_HANDLE;
  VkPipelineLayout _layout = VK_NULL_HANDLE;
  VkPipeline _pipeline = VK_NULL_HANDLE;
  VkFormat _format = VK_FORMAT_UNDEFINED;
};

bool is_srgb(VkFormat format)
{
  return format == VK_FORMAT_B8G8R8A8_SRGB || format == VK_FORMAT_R8G8B8A8_SRGB || format == VK_FORMAT_A8B8G8R8_SRGB_PACK32;
}

// ---- the window renderer: a swapchain, two frames in flight.
class vulkan_renderer_t final : public renderer_t
{
public:
  vulkan_renderer_t() = default;
  vulkan_renderer_t(const vulkan_renderer_t &) = delete;
  vulkan_renderer_t &operator=(const vulkan_renderer_t &) = delete;
  ~vulkan_renderer_t() override
  {
    if (_d.device)
      _d.vkDeviceWaitIdle(_d.device);
    destroy_swapchain();
    for (auto &frame : _frames)
    {
      release(_d, frame.prims);
      if (frame.acquired)
        _d.vkDestroySemaphore(_d.device, frame.acquired, nullptr);
      if (frame.fence)
        _d.vkDestroyFence(_d.device, frame.fence, nullptr);
    }
    if (_pool)
      _d.vkDestroyCommandPool(_d.device, _pool, nullptr);
    _pipeline.reset();
    if (_surface && _d.vkDestroySurfaceKHR)
      _d.vkDestroySurfaceKHR(_d.instance, _surface, nullptr);
  }

  bool open(window_t &window, const std::optional<vulkan_device_t> &shared, std::string &why)
  {
    const auto platform = window.native().platform;
    const auto extensions = vulkan::required_instance_extensions(platform);
    if (shared)
    {
      if (!borrow_device(_d, *shared, why))
        return false;
    }
    else if (!create_instance(_d, extensions, why))
      return false;

    auto surface = vulkan::create_surface(window, _d.instance, reinterpret_cast<vulkan::get_instance_proc_addr_t>(_d.get_instance));
    if (!surface)
    {
      why = "vkCreate*SurfaceKHR failed: " + surface.error().msg;
      return false;
    }
    _surface = reinterpret_cast<VkSurfaceKHR>(*surface);
    if (shared)
    {
      VkBool32 present = VK_FALSE;
      _d.vkGetPhysicalDeviceSurfaceSupportKHR(_d.physical, _d.family, _surface, &present);
      if (!present)
      {
        why = "the program's queue family cannot present to this window";
        return false;
      }
    }
    else if (!create_device(_d, _surface, why))
      return false;
    finish_device(_d);

    VkCommandPoolCreateInfo pool_info{VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO};
    pool_info.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    pool_info.queueFamilyIndex = _d.family;
    if (_d.vkCreateCommandPool(_d.device, &pool_info, nullptr, &_pool) != VK_SUCCESS)
    {
      why = "vkCreateCommandPool failed";
      return false;
    }
    for (auto &frame : _frames)
    {
      VkCommandBufferAllocateInfo allocate{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
      allocate.commandPool = _pool;
      allocate.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
      allocate.commandBufferCount = 1;
      VkSemaphoreCreateInfo semaphore{VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO};
      VkFenceCreateInfo fence{VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};
      fence.flags = VK_FENCE_CREATE_SIGNALED_BIT;
      if (_d.vkAllocateCommandBuffers(_d.device, &allocate, &frame.cmd) != VK_SUCCESS || _d.vkCreateSemaphore(_d.device, &semaphore, nullptr, &frame.acquired) != VK_SUCCESS ||
          _d.vkCreateFence(_d.device, &fence, nullptr, &frame.fence) != VK_SUCCESS)
      {
        why = "per-frame Vulkan objects could not be made";
        return false;
      }
    }
    return true;
  }

  [[nodiscard]] std::string describe() const override
  {
    return "vulkan: " + _d.name;
  }

  bool render(const display_list_t &list) override
  {
    if (list.framebuffer.width <= 0 || list.framebuffer.height <= 0)
      return true;
    for (int attempt = 0; attempt < 2; ++attempt)
    {
      if (!_swapchain || _stale || _wanted.width != list.framebuffer.width || _wanted.height != list.framebuffer.height)
      {
        _wanted = list.framebuffer;
        if (!create_swapchain())
          return !_lost;
        if (!_swapchain)
          return true; // minimised: nothing to draw into
      }
      auto &frame = _frames[_index];
      _d.vkWaitForFences(_d.device, 1, &frame.fence, VK_TRUE, UINT64_MAX);
      std::uint32_t image = 0;
      const VkResult acquired = _d.vkAcquireNextImageKHR(_d.device, _swapchain, UINT64_MAX, frame.acquired, VK_NULL_HANDLE, &image);
      if (acquired == VK_ERROR_OUT_OF_DATE_KHR)
      {
        _stale = true;
        continue;
      }
      if (acquired != VK_SUCCESS && acquired != VK_SUBOPTIMAL_KHR)
        return false;
      _d.vkResetFences(_d.device, 1, &frame.fence);
      if (!_pipeline->upload(frame.prims, list.prims))
        return false;

      VkCommandBufferBeginInfo begin{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
      begin.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
      _d.vkBeginCommandBuffer(frame.cmd, &begin);
      _pipeline->record(frame.cmd, _framebuffers[image], _extent, frame.prims, list, !is_srgb(_pipeline->format()));
      _d.vkEndCommandBuffer(frame.cmd);

      const VkPipelineStageFlags wait_stage = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
      VkSubmitInfo submit{VK_STRUCTURE_TYPE_SUBMIT_INFO};
      submit.waitSemaphoreCount = 1;
      submit.pWaitSemaphores = &frame.acquired;
      submit.pWaitDstStageMask = &wait_stage;
      submit.commandBufferCount = 1;
      submit.pCommandBuffers = &frame.cmd;
      submit.signalSemaphoreCount = 1;
      submit.pSignalSemaphores = &_rendered[image];
      if (_d.vkQueueSubmit(_d.queue, 1, &submit, frame.fence) != VK_SUCCESS)
        return false;
      VkPresentInfoKHR present{VK_STRUCTURE_TYPE_PRESENT_INFO_KHR};
      present.waitSemaphoreCount = 1;
      present.pWaitSemaphores = &_rendered[image];
      present.swapchainCount = 1;
      present.pSwapchains = &_swapchain;
      present.pImageIndices = &image;
      const VkResult presented = _d.vkQueuePresentKHR(_d.queue, &present);
      _index = (_index + 1) % _frames.size();
      if (presented == VK_ERROR_OUT_OF_DATE_KHR || presented == VK_SUBOPTIMAL_KHR)
        _stale = true;
      else if (presented != VK_SUCCESS)
        return false;
      return true;
    }
    return true;
  }

private:
  struct frame_slot_t
  {
    VkCommandBuffer cmd = VK_NULL_HANDLE;
    VkSemaphore acquired = VK_NULL_HANDLE;
    VkFence fence = VK_NULL_HANDLE;
    buffer_t prims;
  };

  // Returns false only on a failure that ends the renderer (`_lost`); a surface with no area leaves
  // `_swapchain` null and succeeds.
  bool create_swapchain()
  {
    _d.vkDeviceWaitIdle(_d.device);
    _stale = false;
    VkSurfaceCapabilitiesKHR caps;
    if (_d.vkGetPhysicalDeviceSurfaceCapabilitiesKHR(_d.physical, _surface, &caps) != VK_SUCCESS)
      return lose();
    VkExtent2D extent = caps.currentExtent;
    if (extent.width == 0xFFFFFFFFu)
    {
      extent.width = std::clamp(std::uint32_t(_wanted.width), caps.minImageExtent.width, caps.maxImageExtent.width);
      extent.height = std::clamp(std::uint32_t(_wanted.height), caps.minImageExtent.height, caps.maxImageExtent.height);
    }
    if (extent.width == 0 || extent.height == 0)
    {
      destroy_swapchain();
      return true;
    }

    std::uint32_t count = 0;
    _d.vkGetPhysicalDeviceSurfaceFormatsKHR(_d.physical, _surface, &count, nullptr);
    std::vector<VkSurfaceFormatKHR> formats(count);
    _d.vkGetPhysicalDeviceSurfaceFormatsKHR(_d.physical, _surface, &count, formats.data());
    if (formats.empty())
      return lose();
    VkSurfaceFormatKHR chosen = formats[0];
    for (const auto &format : formats)
    {
      if (is_srgb(format.format) && format.colorSpace == VK_COLOR_SPACE_SRGB_NONLINEAR_KHR)
      {
        chosen = format;
        break;
      }
    }

    VkSwapchainCreateInfoKHR info{VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR};
    info.surface = _surface;
    info.minImageCount = caps.maxImageCount ? std::min(caps.minImageCount + 1, caps.maxImageCount) : caps.minImageCount + 1;
    info.imageFormat = chosen.format;
    info.imageColorSpace = chosen.colorSpace;
    info.imageExtent = extent;
    info.imageArrayLayers = 1;
    info.imageUsage = VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT;
    info.imageSharingMode = VK_SHARING_MODE_EXCLUSIVE;
    info.preTransform = (caps.supportedTransforms & VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR) ? VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR : caps.currentTransform;
    info.compositeAlpha = VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR;
    for (auto bit : {VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR, VK_COMPOSITE_ALPHA_INHERIT_BIT_KHR, VK_COMPOSITE_ALPHA_PRE_MULTIPLIED_BIT_KHR, VK_COMPOSITE_ALPHA_POST_MULTIPLIED_BIT_KHR})
    {
      if (caps.supportedCompositeAlpha & bit)
      {
        info.compositeAlpha = bit;
        break;
      }
    }
    // FIFO is the one mode every implementation has, and frames are paced by the window layer anyway.
    info.presentMode = VK_PRESENT_MODE_FIFO_KHR;
    info.clipped = VK_TRUE;
    info.oldSwapchain = _swapchain;
    VkSwapchainKHR made = VK_NULL_HANDLE;
    if (_d.vkCreateSwapchainKHR(_d.device, &info, nullptr, &made) != VK_SUCCESS)
      return lose();
    destroy_swapchain();
    _swapchain = made;
    _extent = extent;

    if (!_pipeline || _pipeline->format() != chosen.format)
    {
      _pipeline.reset();
      _pipeline = std::make_unique<pipeline_t>(_d);
      std::string why;
      if (!_pipeline->create(chosen.format, VK_IMAGE_LAYOUT_PRESENT_SRC_KHR, why))
        return lose();
    }

    _d.vkGetSwapchainImagesKHR(_d.device, _swapchain, &count, nullptr);
    _images.resize(count);
    _d.vkGetSwapchainImagesKHR(_d.device, _swapchain, &count, _images.data());
    for (auto image : _images)
    {
      VkImageViewCreateInfo view_info{VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO};
      view_info.image = image;
      view_info.viewType = VK_IMAGE_VIEW_TYPE_2D;
      view_info.format = chosen.format;
      view_info.subresourceRange = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1};
      VkImageView view = VK_NULL_HANDLE;
      if (_d.vkCreateImageView(_d.device, &view_info, nullptr, &view) != VK_SUCCESS)
        return lose();
      _views.push_back(view);
      VkFramebufferCreateInfo fb_info{VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO};
      fb_info.renderPass = _pipeline->pass();
      fb_info.attachmentCount = 1;
      fb_info.pAttachments = &view;
      fb_info.width = extent.width;
      fb_info.height = extent.height;
      fb_info.layers = 1;
      VkFramebuffer framebuffer = VK_NULL_HANDLE;
      if (_d.vkCreateFramebuffer(_d.device, &fb_info, nullptr, &framebuffer) != VK_SUCCESS)
        return lose();
      _framebuffers.push_back(framebuffer);
      // One per image: a semaphore a present still waits on must not be signalled again.
      VkSemaphoreCreateInfo semaphore{VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO};
      VkSemaphore rendered = VK_NULL_HANDLE;
      if (_d.vkCreateSemaphore(_d.device, &semaphore, nullptr, &rendered) != VK_SUCCESS)
        return lose();
      _rendered.push_back(rendered);
    }
    return true;
  }

  bool lose()
  {
    _lost = true;
    return false;
  }

  void destroy_swapchain()
  {
    for (auto framebuffer : _framebuffers)
      _d.vkDestroyFramebuffer(_d.device, framebuffer, nullptr);
    for (auto view : _views)
      _d.vkDestroyImageView(_d.device, view, nullptr);
    for (auto semaphore : _rendered)
      _d.vkDestroySemaphore(_d.device, semaphore, nullptr);
    _framebuffers.clear();
    _views.clear();
    _rendered.clear();
    _images.clear();
    if (_swapchain)
      _d.vkDestroySwapchainKHR(_d.device, _swapchain, nullptr);
    _swapchain = VK_NULL_HANDLE;
  }

  // Declared first, destroyed last: everything below is made from it.
  device_t _d;
  VkSurfaceKHR _surface = VK_NULL_HANDLE;
  VkCommandPool _pool = VK_NULL_HANDLE;
  std::unique_ptr<pipeline_t> _pipeline;
  std::array<frame_slot_t, 2> _frames{};
  std::size_t _index = 0;
  VkSwapchainKHR _swapchain = VK_NULL_HANDLE;
  VkExtent2D _extent{};
  extent_t _wanted;
  bool _stale = false;
  bool _lost = false;
  std::vector<VkImage> _images;
  std::vector<VkImageView> _views;
  std::vector<VkFramebuffer> _framebuffers;
  std::vector<VkSemaphore> _rendered;
};
} // namespace

std::unique_ptr<renderer_t> make_vulkan_renderer(window_t &window, const std::optional<vulkan_device_t> &shared, std::string &why)
{
  if (std::size(shaders::ui_vertex) < 5 || std::size(shaders::ui_fragment) < 5)
  {
    why = "the UI shaders have not been generated";
    return nullptr;
  }
  auto renderer = std::make_unique<vulkan_renderer_t>();
  if (!renderer->open(window, shared, why))
    return nullptr;
  return renderer;
}

// Render one display list into an image of our own and read it back: no window, no surface, which
// is what lets the pipeline be tested headless on lavapipe.
std::optional<offscreen_image_t> render_offscreen_vulkan(const display_list_t &list, std::string &why)
{
  if (list.framebuffer.width <= 0 || list.framebuffer.height <= 0)
  {
    why = "empty framebuffer";
    return std::nullopt;
  }
  device_t d;
  if (!create_instance(d, {}, why) || !create_device(d, VK_NULL_HANDLE, why))
    return std::nullopt;
  finish_device(d);

  const VkFormat format = VK_FORMAT_R8G8B8A8_SRGB;
  const VkExtent2D extent{std::uint32_t(list.framebuffer.width), std::uint32_t(list.framebuffer.height)};
  pipeline_t pipeline(d);
  if (!pipeline.create(format, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, why))
    return std::nullopt;

  VkImage image = VK_NULL_HANDLE;
  VkDeviceMemory image_memory = VK_NULL_HANDLE;
  VkImageView view = VK_NULL_HANDLE;
  VkFramebuffer framebuffer = VK_NULL_HANDLE;
  VkCommandPool pool = VK_NULL_HANDLE;
  VkFence fence = VK_NULL_HANDLE;
  buffer_t prims;
  buffer_t readback;
  std::optional<offscreen_image_t> result;
  [&]
  {
    VkImageCreateInfo image_info{VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO};
    image_info.imageType = VK_IMAGE_TYPE_2D;
    image_info.format = format;
    image_info.extent = {extent.width, extent.height, 1};
    image_info.mipLevels = 1;
    image_info.arrayLayers = 1;
    image_info.samples = VK_SAMPLE_COUNT_1_BIT;
    image_info.tiling = VK_IMAGE_TILING_OPTIMAL;
    image_info.usage = VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT | VK_IMAGE_USAGE_TRANSFER_SRC_BIT;
    image_info.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    if (d.vkCreateImage(d.device, &image_info, nullptr, &image) != VK_SUCCESS)
    {
      why = "vkCreateImage failed";
      return;
    }
    VkMemoryRequirements requirements;
    d.vkGetImageMemoryRequirements(d.device, image, &requirements);
    auto type = d.memory_type(requirements.memoryTypeBits, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
    if (!type)
      type = d.memory_type(requirements.memoryTypeBits, 0);
    VkMemoryAllocateInfo allocate{VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO};
    allocate.allocationSize = requirements.size;
    allocate.memoryTypeIndex = type.value_or(0);
    if (!type || d.vkAllocateMemory(d.device, &allocate, nullptr, &image_memory) != VK_SUCCESS)
    {
      why = "no memory for the offscreen image";
      return;
    }
    d.vkBindImageMemory(d.device, image, image_memory, 0);
    VkImageViewCreateInfo view_info{VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO};
    view_info.image = image;
    view_info.viewType = VK_IMAGE_VIEW_TYPE_2D;
    view_info.format = format;
    view_info.subresourceRange = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1};
    d.vkCreateImageView(d.device, &view_info, nullptr, &view);
    VkFramebufferCreateInfo fb_info{VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO};
    fb_info.renderPass = pipeline.pass();
    fb_info.attachmentCount = 1;
    fb_info.pAttachments = &view;
    fb_info.width = extent.width;
    fb_info.height = extent.height;
    fb_info.layers = 1;
    d.vkCreateFramebuffer(d.device, &fb_info, nullptr, &framebuffer);

    const VkDeviceSize bytes = VkDeviceSize(extent.width) * extent.height * 4;
    if (!pipeline.upload(prims, list.prims) || !make_buffer(d, readback, bytes, VK_BUFFER_USAGE_TRANSFER_DST_BIT))
    {
      why = "buffers could not be made";
      return;
    }

    VkCommandPoolCreateInfo pool_info{VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO};
    pool_info.queueFamilyIndex = d.family;
    d.vkCreateCommandPool(d.device, &pool_info, nullptr, &pool);
    VkCommandBufferAllocateInfo allocate_cmd{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
    allocate_cmd.commandPool = pool;
    allocate_cmd.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocate_cmd.commandBufferCount = 1;
    VkCommandBuffer cmd = VK_NULL_HANDLE;
    d.vkAllocateCommandBuffers(d.device, &allocate_cmd, &cmd);
    VkCommandBufferBeginInfo begin{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    begin.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    d.vkBeginCommandBuffer(cmd, &begin);
    pipeline.record(cmd, framebuffer, extent, prims, list, false);
    // The pass leaves the image in TRANSFER_SRC_OPTIMAL, but its implicit dependency to what follows
    // makes no writes visible to a transfer: the copy needs its own barrier, and the host read
    // after the fence another.
    VkMemoryBarrier rendered{VK_STRUCTURE_TYPE_MEMORY_BARRIER};
    rendered.srcAccessMask = VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT;
    rendered.dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT;
    d.vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT, 0, 1, &rendered, 0, nullptr, 0, nullptr);
    VkBufferImageCopy region{};
    region.imageSubresource = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 0, 1};
    region.imageExtent = {extent.width, extent.height, 1};
    d.vkCmdCopyImageToBuffer(cmd, image, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, readback.buffer, 1, &region);
    VkMemoryBarrier copied{VK_STRUCTURE_TYPE_MEMORY_BARRIER};
    copied.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
    copied.dstAccessMask = VK_ACCESS_HOST_READ_BIT;
    d.vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_HOST_BIT, 0, 1, &copied, 0, nullptr, 0, nullptr);
    d.vkEndCommandBuffer(cmd);
    VkFenceCreateInfo fence_info{VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};
    d.vkCreateFence(d.device, &fence_info, nullptr, &fence);
    VkSubmitInfo submit{VK_STRUCTURE_TYPE_SUBMIT_INFO};
    submit.commandBufferCount = 1;
    submit.pCommandBuffers = &cmd;
    if (d.vkQueueSubmit(d.queue, 1, &submit, fence) != VK_SUCCESS)
    {
      why = "vkQueueSubmit failed";
      return;
    }
    d.vkWaitForFences(d.device, 1, &fence, VK_TRUE, UINT64_MAX);
    offscreen_image_t out;
    out.extent = list.framebuffer;
    out.device = d.name;
    out.rgba.resize(std::size_t(bytes));
    std::memcpy(out.rgba.data(), readback.mapped, out.rgba.size());
    result = std::move(out);
  }();

  if (fence)
    d.vkDestroyFence(d.device, fence, nullptr);
  if (pool)
    d.vkDestroyCommandPool(d.device, pool, nullptr);
  release(d, prims);
  release(d, readback);
  if (framebuffer)
    d.vkDestroyFramebuffer(d.device, framebuffer, nullptr);
  if (view)
    d.vkDestroyImageView(d.device, view, nullptr);
  if (image)
    d.vkDestroyImage(d.device, image, nullptr);
  if (image_memory)
    d.vkFreeMemory(d.device, image_memory, nullptr);
  return result;
}
} // namespace vio::gui::ui::detail
