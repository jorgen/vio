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

#define GL_SILENCE_DEPRECATION

#include <algorithm>
#include <cmath>
#include <memory>
#include <string>
#include <vector>

#include <dlfcn.h>
#include <poll.h>
#include <cstdio>
#include <cstdlib>
#define VIO_TRACE(...) do { if (std::getenv("VIO_GUI_TRACE")) std::fprintf(stderr, __VA_ARGS__); } while (0)

#include "vio/gui/backends.h"
#include "vio/gui/context.h"
#include "vio/gui/gui.h"

#import <Cocoa/Cocoa.h>
#import <OpenGL/OpenGL.h>
#import <QuartzCore/CAMetalLayer.h>

namespace vio::gui::detail
{
class cocoa_window_t;
class cocoa_thread_t;
}

@interface VioView : NSView
{
@public
  vio::gui::detail::cocoa_window_t *owner;
  NSTrackingArea *tracking;
}
@end

@interface VioWindowDelegate : NSObject <NSWindowDelegate>
{
@public
  vio::gui::detail::cocoa_window_t *owner;
}
@end

@interface VioWindow : NSWindow
@end

@implementation VioWindow
- (BOOL)canBecomeKeyWindow
{
  return YES;
}
- (BOOL)canBecomeMainWindow
{
  return YES;
}
@end

namespace vio::gui::detail
{
namespace
{
constexpr short wake_subtype = 0x7669;

key_t translate_key(unsigned short code)
{
  switch (code)
  {
  case 0x00: return key_t::a;
  case 0x0B: return key_t::b;
  case 0x08: return key_t::c;
  case 0x02: return key_t::d;
  case 0x0E: return key_t::e;
  case 0x03: return key_t::f;
  case 0x05: return key_t::g;
  case 0x04: return key_t::h;
  case 0x22: return key_t::i;
  case 0x26: return key_t::j;
  case 0x28: return key_t::k;
  case 0x25: return key_t::l;
  case 0x2E: return key_t::m;
  case 0x2D: return key_t::n;
  case 0x1F: return key_t::o;
  case 0x23: return key_t::p;
  case 0x0C: return key_t::q;
  case 0x0F: return key_t::r;
  case 0x01: return key_t::s;
  case 0x11: return key_t::t;
  case 0x20: return key_t::u;
  case 0x09: return key_t::v;
  case 0x0D: return key_t::w;
  case 0x07: return key_t::x;
  case 0x10: return key_t::y;
  case 0x06: return key_t::z;
  case 0x1D: return key_t::digit_0;
  case 0x12: return key_t::digit_1;
  case 0x13: return key_t::digit_2;
  case 0x14: return key_t::digit_3;
  case 0x15: return key_t::digit_4;
  case 0x17: return key_t::digit_5;
  case 0x16: return key_t::digit_6;
  case 0x1A: return key_t::digit_7;
  case 0x1C: return key_t::digit_8;
  case 0x19: return key_t::digit_9;
  case 0x31: return key_t::space;
  case 0x27: return key_t::apostrophe;
  case 0x2B: return key_t::comma;
  case 0x1B: return key_t::minus;
  case 0x2F: return key_t::period;
  case 0x2C: return key_t::slash;
  case 0x29: return key_t::semicolon;
  case 0x18: return key_t::equal;
  case 0x21: return key_t::left_bracket;
  case 0x2A: return key_t::backslash;
  case 0x1E: return key_t::right_bracket;
  case 0x32: return key_t::grave_accent;
  case 0x35: return key_t::escape;
  case 0x24: return key_t::enter;
  case 0x30: return key_t::tab;
  case 0x33: return key_t::backspace;
  case 0x72: return key_t::insert;
  case 0x75: return key_t::delete_key;
  case 0x7C: return key_t::right;
  case 0x7B: return key_t::left;
  case 0x7D: return key_t::down;
  case 0x7E: return key_t::up;
  case 0x74: return key_t::page_up;
  case 0x79: return key_t::page_down;
  case 0x73: return key_t::home;
  case 0x77: return key_t::end;
  case 0x39: return key_t::caps_lock;
  case 0x47: return key_t::num_lock;
  case 0x7A: return key_t::f1;
  case 0x78: return key_t::f2;
  case 0x63: return key_t::f3;
  case 0x76: return key_t::f4;
  case 0x60: return key_t::f5;
  case 0x61: return key_t::f6;
  case 0x62: return key_t::f7;
  case 0x64: return key_t::f8;
  case 0x65: return key_t::f9;
  case 0x6D: return key_t::f10;
  case 0x67: return key_t::f11;
  case 0x6F: return key_t::f12;
  case 0x52: return key_t::keypad_0;
  case 0x53: return key_t::keypad_1;
  case 0x54: return key_t::keypad_2;
  case 0x55: return key_t::keypad_3;
  case 0x56: return key_t::keypad_4;
  case 0x57: return key_t::keypad_5;
  case 0x58: return key_t::keypad_6;
  case 0x59: return key_t::keypad_7;
  case 0x5B: return key_t::keypad_8;
  case 0x5C: return key_t::keypad_9;
  case 0x41: return key_t::keypad_decimal;
  case 0x4B: return key_t::keypad_divide;
  case 0x43: return key_t::keypad_multiply;
  case 0x4E: return key_t::keypad_subtract;
  case 0x45: return key_t::keypad_add;
  case 0x4C: return key_t::keypad_enter;
  case 0x51: return key_t::keypad_equal;
  case 0x38: return key_t::left_shift;
  case 0x3B: return key_t::left_control;
  case 0x3A: return key_t::left_alt;
  case 0x37: return key_t::left_super;
  case 0x3C: return key_t::right_shift;
  case 0x3E: return key_t::right_control;
  case 0x3D: return key_t::right_alt;
  case 0x36: return key_t::right_super;
  case 0x6E: return key_t::menu;
  default: return key_t::unknown;
  }
}

modifier_t translate_flags(NSEventModifierFlags flags)
{
  auto modifiers = modifier_t::none;
  if (flags & NSEventModifierFlagShift)
    modifiers = modifiers | modifier_t::shift;
  if (flags & NSEventModifierFlagControl)
    modifiers = modifiers | modifier_t::control;
  if (flags & NSEventModifierFlagOption)
    modifiers = modifiers | modifier_t::alt;
  if (flags & NSEventModifierFlagCommand)
    modifiers = modifiers | modifier_t::super;
  if (flags & NSEventModifierFlagCapsLock)
    modifiers = modifiers | modifier_t::caps_lock;
  return modifiers;
}

NSEventModifierFlags flag_for(key_t key)
{
  switch (key)
  {
  case key_t::left_shift:
  case key_t::right_shift: return NSEventModifierFlagShift;
  case key_t::left_control:
  case key_t::right_control: return NSEventModifierFlagControl;
  case key_t::left_alt:
  case key_t::right_alt: return NSEventModifierFlagOption;
  case key_t::left_super:
  case key_t::right_super: return NSEventModifierFlagCommand;
  case key_t::caps_lock: return NSEventModifierFlagCapsLock;
  default: return 0;
  }
}

NSCursor *cursor_for(cursor_t cursor)
{
  switch (cursor)
  {
  case cursor_t::text: return [NSCursor IBeamCursor];
  case cursor_t::hand: return [NSCursor pointingHandCursor];
  case cursor_t::crosshair: return [NSCursor crosshairCursor];
  case cursor_t::resize_horizontal: return [NSCursor resizeLeftRightCursor];
  case cursor_t::resize_vertical: return [NSCursor resizeUpDownCursor];
  case cursor_t::resize_all: return [NSCursor closedHandCursor];
  case cursor_t::not_allowed: return [NSCursor operationNotAllowedCursor];
  default: return [NSCursor arrowCursor];
  }
}

std::int64_t refresh_interval(std::int64_t configured)
{
  if (configured > 0)
    return configured;
  NSScreen *screen = [NSScreen mainScreen];
  if (@available(macOS 12.0, *))
  {
    const NSInteger rate = screen ? screen.maximumFramesPerSecond : 0;
    if (rate > 0)
      return 1'000'000'000 / rate;
  }
  return 16'666'667;
}

enum class wait_state_t
{
  idle,
  waiting,
  polling
};
} // namespace

class cocoa_thread_t final : public vio::detail::host_wait_t
{
public:
  explicit cocoa_thread_t(loop_core_t &core)
    : core(core)
  {
  }

  ~cocoa_thread_t() override
  {
    core.set_host_wait(nullptr);
    if (_observer)
    {
      CFRunLoopObserverInvalidate(_observer);
      CFRelease(_observer);
    }
    drop_timer();
    if (_source)
    {
      CFRunLoopRemoveSource(CFRunLoopGetMain(), _source, kCFRunLoopCommonModes);
      CFRelease(_source);
    }
    if (_descriptor)
    {
      CFFileDescriptorInvalidate(_descriptor);
      CFRelease(_descriptor);
    }
  }

  int start()
  {
    if (![NSThread isMainThread])
      return errc::not_supported;
    [NSApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    if (![[NSRunningApplication currentApplication] isFinishedLaunching])
      [NSApp finishLaunching];
    const auto handle = core.backend().native_handle();
    if (handle < 0)
      return errc::not_supported;
    CFRunLoopAddCommonMode(CFRunLoopGetMain(), (__bridge CFStringRef)NSEventTrackingRunLoopMode);
    CFRunLoopAddCommonMode(CFRunLoopGetMain(), (__bridge CFStringRef)NSModalPanelRunLoopMode);
    CFFileDescriptorContext context{0, this, nullptr, nullptr, nullptr};
    _descriptor = CFFileDescriptorCreate(kCFAllocatorDefault, static_cast<int>(handle), false, &cocoa_thread_t::on_descriptor, &context);
    if (!_descriptor)
      return errc::out_of_memory;
    CFFileDescriptorEnableCallBacks(_descriptor, kCFFileDescriptorReadCallBack);
    _source = CFFileDescriptorCreateRunLoopSource(kCFAllocatorDefault, _descriptor, 0);
    CFRunLoopAddSource(CFRunLoopGetMain(), _source, kCFRunLoopCommonModes);
    CFRunLoopObserverContext observer_context{0, this, nullptr, nullptr, nullptr};
    _observer = CFRunLoopObserverCreate(kCFAllocatorDefault, kCFRunLoopBeforeWaiting, true, 0, &cocoa_thread_t::on_before_waiting, &observer_context);
    CFRunLoopAddObserver(CFRunLoopGetMain(), _observer, kCFRunLoopCommonModes);
    core.set_host_wait(this);
    return 0;
  }

  void wait(std::int64_t timeout_ns) override
  {
    arm_timer();
    if (timeout_ns == 0)
      return;
    NSDate *until = timeout_ns < 0 ? [NSDate distantFuture] : [NSDate dateWithTimeIntervalSinceNow:static_cast<double>(timeout_ns) / 1e9];
    _state = wait_state_t::waiting;
    NSEvent *event = [NSApp nextEventMatchingMask:NSEventMaskAny untilDate:until inMode:NSDefaultRunLoopMode dequeue:YES];
    _state = wait_state_t::idle;
    if (event && !is_wake(event))
      _pending.push_back(event);
  }

  void dispatch()
  {
    @autoreleasepool
    {
      auto pending = std::move(_pending);
      _pending.clear();
      for (NSEvent *event : pending)
        [NSApp sendEvent:event];
      for (;;)
      {
        _state = wait_state_t::polling;
        NSEvent *event = [NSApp nextEventMatchingMask:NSEventMaskAny untilDate:[NSDate distantPast] inMode:NSDefaultRunLoopMode dequeue:YES];
        _state = wait_state_t::idle;
        if (!event)
          break;
        if (!is_wake(event))
          [NSApp sendEvent:event];
      }
      [NSApp updateWindows];
    }
  }

  void nested_turn()
  {
    VIO_TRACE("nested_turn state=%d\n", static_cast<int>(_state));
    if (_state != wait_state_t::idle)
      return;
    core.run_nested();
    arm_timer();
  }

  loop_core_t &core;
  std::size_t displays = 0;

private:
  static bool is_wake(NSEvent *event)
  {
    return event.type == NSEventTypeApplicationDefined && event.subtype == wake_subtype;
  }

  void post_wake()
  {
    NSEvent *event = [NSEvent otherEventWithType:NSEventTypeApplicationDefined location:NSZeroPoint modifierFlags:0 timestamp:0 windowNumber:0 context:nil subtype:wake_subtype data1:0 data2:0];
    [NSApp postEvent:event atStart:NO];
  }

  CFRunLoopTimerRef make_timer(double delay)
  {
    CFRunLoopTimerContext context{0, this, nullptr, nullptr, nullptr};
    CFRunLoopTimerRef timer = CFRunLoopTimerCreate(kCFAllocatorDefault, CFAbsoluteTimeGetCurrent() + delay, 0, 0, 0, &cocoa_thread_t::on_timer, &context);
    CFRunLoopAddTimer(CFRunLoopGetMain(), timer, kCFRunLoopCommonModes);
    return timer;
  }

  void arm_timer(bool now = false)
  {
    const std::int64_t next = core.next_timeout();
    if (next < 0 && !now)
    {
      drop_timer();
      return;
    }
    const double delay = now ? 0 : static_cast<double>(std::max<std::int64_t>(next, 1'000'000)) / 1e9;
    const double when = CFAbsoluteTimeGetCurrent() + delay;
    VIO_TRACE("arm next=%lld delay=%f\n", static_cast<long long>(next), delay);
    if (_timer && _timer != _firing && CFRunLoopTimerIsValid(_timer) && std::abs(CFRunLoopTimerGetNextFireDate(_timer) - when) < 0.0005)
      return;
    drop_timer();
    _timer = make_timer(delay);
  }

  void drop_timer()
  {
    if (!_timer)
      return;
    CFRunLoopTimerInvalidate(_timer);
    CFRelease(_timer);
    _timer = nullptr;
  }

  static void on_descriptor(CFFileDescriptorRef descriptor, CFOptionFlags, void *info)
  {
    auto *self = static_cast<cocoa_thread_t *>(info);
    VIO_TRACE("on_descriptor state=%d\n", static_cast<int>(self->_state));
    CFFileDescriptorEnableCallBacks(descriptor, kCFFileDescriptorReadCallBack);
    if (self->_state == wait_state_t::waiting)
    {
      self->post_wake();
      return;
    }
    ++self->_in_descriptor;
    self->nested_turn();
    --self->_in_descriptor;
  }

  static void on_before_waiting(CFRunLoopObserverRef, CFRunLoopActivity, void *info)
  {
    auto *self = static_cast<cocoa_thread_t *>(info);
    pollfd descriptor{static_cast<int>(self->core.backend().native_handle()), POLLIN, 0};
    self->arm_timer(self->_in_descriptor > 0 && ::poll(&descriptor, 1, 0) > 0);
  }

  static void on_timer(CFRunLoopTimerRef timer, void *info)
  {
    auto *self = static_cast<cocoa_thread_t *>(info);
    VIO_TRACE("on_timer state=%d\n", static_cast<int>(self->_state));
    if (self->_state == wait_state_t::waiting)
    {
      self->post_wake();
      return;
    }
    if (self->_state != wait_state_t::idle)
      return;
    auto *outer = std::exchange(self->_firing, timer);
    self->nested_turn();
    self->_firing = outer;
  }

  CFFileDescriptorRef _descriptor = nullptr;
  CFRunLoopSourceRef _source = nullptr;
  CFRunLoopTimerRef _timer = nullptr;
  CFRunLoopObserverRef _observer = nullptr;
  CFRunLoopTimerRef _firing = nullptr;
  int _in_descriptor = 0;
  std::vector<NSEvent *> _pending;
  wait_state_t _state = wait_state_t::idle;
};

namespace
{
std::weak_ptr<cocoa_thread_t> current_thread;
}

class cocoa_display_t;

class cocoa_window_t final : public window_backend_t
{
public:
  cocoa_window_t(cocoa_display_t &display, window_impl_t &window);
  ~cocoa_window_t() override;

  int create(const window_config_t &config);

  void set_title(std::string_view title) override;
  int set_size(extent_t size) override;
  int set_position(point_t position) override;
  [[nodiscard]] std::expected<point_t, int> position() const override;
  void set_size_limits(extent_t min_size, extent_t max_size) override;
  void set_visible(bool visible) override;
  void set_fullscreen(bool fullscreen) override;
  void minimize() override;
  void maximize() override;
  void restore() override;
  void focus() override;
  void set_cursor(cursor_t cursor) override;
  void frame_wanted() override;
  [[nodiscard]] native_window_t native() const override;

  void report_size();
  void update_visibility();
  void live_resize();
  void apply_cursor();
  void cursor_left();

  window_impl_t &window;
  VioWindow *ns_window = nil;
  VioView *view = nil;
  VioWindowDelegate *delegate = nil;
  CAMetalLayer *metal_layer = nil;
  cocoa_display_t &display;
  modifier_t modifiers = modifier_t::none;
  bool occluded = false;

private:
  static void tick(void *context);

  frame_clock_t _clock;
  cursor_t _cursor = cursor_t::arrow;
  bool _cursor_hidden = false;
};

class cocoa_display_t final : public display_backend_t
{
public:
  explicit cocoa_display_t(display_impl_t &display)
    : impl(display)
  {
  }

  ~cocoa_display_t() override
  {
    if (thread && --thread->displays == 0)
      current_thread.reset();
  }

  int open()
  {
    thread = current_thread.lock();
    if (!thread)
    {
      thread = std::make_shared<cocoa_thread_t>(impl.core);
      if (int result = thread->start(); result < 0)
        return result;
      current_thread = thread;
    }
    else if (&thread->core != &impl.core)
    {
      return errc::busy;
    }
    ++thread->displays;
    return 0;
  }

  [[nodiscard]] const char *name() const noexcept override
  {
    return "cocoa";
  }
  [[nodiscard]] platform_t platform() const noexcept override
  {
    return platform_t::cocoa;
  }

  std::expected<std::unique_ptr<window_backend_t>, int> create_window(window_impl_t &window, const window_config_t &config) override
  {
    auto made = std::make_unique<cocoa_window_t>(*this, window);
    if (int result = made->create(config); result < 0)
      return std::unexpected(result);
    return made;
  }

  void dispatch() override
  {
    thread->dispatch();
  }

  void set_clipboard_text(std::string text) override
  {
    NSPasteboard *board = [NSPasteboard generalPasteboard];
    [board clearContents];
    [board setString:[NSString stringWithUTF8String:text.c_str()] forType:NSPasteboardTypeString];
  }

  void request_clipboard_text() override
  {
    NSString *text = [[NSPasteboard generalPasteboard] stringForType:NSPasteboardTypeString];
    impl.clipboard_arrived(std::string(text ? [text UTF8String] : ""));
  }

  [[nodiscard]] void *native_display() const noexcept override
  {
    return (__bridge void *)NSApp;
  }

  void close(loop_core_t &core, posted_t &done) override
  {
    core.defer(done);
  }

  display_impl_t &impl;
  std::shared_ptr<cocoa_thread_t> thread;
};

cocoa_window_t::cocoa_window_t(cocoa_display_t &display, window_impl_t &window)
  : window(window)
  , display(display)
  , _clock(window.display.core, refresh_interval(window.display.config.frame_interval_ns), &cocoa_window_t::tick, this)
{
}

cocoa_window_t::~cocoa_window_t()
{
  if (_cursor_hidden)
    [NSCursor unhide];
  if (view)
    view->owner = nullptr;
  if (delegate)
    delegate->owner = nullptr;
  if (ns_window)
  {
    [ns_window setDelegate:nil];
    [ns_window orderOut:nil];
    [ns_window close];
  }
}

int cocoa_window_t::create(const window_config_t &config)
{
  @autoreleasepool
  {
    NSWindowStyleMask style = NSWindowStyleMaskMiniaturizable;
    if (config.decorated)
    {
      style |= NSWindowStyleMaskTitled | NSWindowStyleMaskClosable;
      if (config.resizable)
        style |= NSWindowStyleMaskResizable;
    }
    else
    {
      style = NSWindowStyleMaskBorderless;
    }
    const NSRect content = NSMakeRect(0, 0, config.size.width, config.size.height);
    ns_window = [[VioWindow alloc] initWithContentRect:content styleMask:style backing:NSBackingStoreBuffered defer:NO];
    if (!ns_window)
      return errc::out_of_memory;
    [ns_window setReleasedWhenClosed:NO];
    view = [[VioView alloc] initWithFrame:content];
    view->owner = this;
    delegate = [[VioWindowDelegate alloc] init];
    delegate->owner = this;
    [ns_window setContentView:view];
    [ns_window setDelegate:delegate];
    [ns_window makeFirstResponder:view];
    [ns_window setAcceptsMouseMovedEvents:YES];
    [ns_window setRestorable:NO];
    [ns_window center];
    if (config.transparent)
    {
      [ns_window setOpaque:NO];
      [ns_window setBackgroundColor:[NSColor clearColor]];
    }
    set_title(config.title);
    set_size_limits(config.min_size, config.max_size);
    report_size();
    if (config.visible)
    {
      [ns_window makeKeyAndOrderFront:nil];
      [NSApp activateIgnoringOtherApps:YES];
    }
    update_visibility();
    if (config.fullscreen)
      set_fullscreen(true);
  }
  return 0;
}

void cocoa_window_t::report_size()
{
  const NSRect bounds = [view bounds];
  const NSRect backing = [view convertRectToBacking:bounds];
  const extent_t size{static_cast<int>(bounds.size.width), static_cast<int>(bounds.size.height)};
  const extent_t framebuffer{static_cast<int>(backing.size.width), static_cast<int>(backing.size.height)};
  const float scale = static_cast<float>([ns_window backingScaleFactor]);
  if (metal_layer)
  {
    metal_layer.contentsScale = scale;
    metal_layer.drawableSize = backing.size;
  }
  window.on_resize(size, framebuffer, scale);
}

void cocoa_window_t::update_visibility()
{
  const bool visible = [ns_window isVisible] && ![ns_window isMiniaturized] && !occluded;
  window.on_visible(visible);
}

void cocoa_window_t::live_resize()
{
  if ([view inLiveResize])
    display.thread->nested_turn();
}

void cocoa_window_t::apply_cursor()
{
  if (_cursor == cursor_t::hidden)
  {
    if (!_cursor_hidden)
    {
      [NSCursor hide];
      _cursor_hidden = true;
    }
    return;
  }
  if (_cursor_hidden)
  {
    [NSCursor unhide];
    _cursor_hidden = false;
  }
  [cursor_for(_cursor) set];
}

void cocoa_window_t::cursor_left()
{
  if (_cursor_hidden)
  {
    [NSCursor unhide];
    _cursor_hidden = false;
  }
  [[NSCursor arrowCursor] set];
}

void cocoa_window_t::set_title(std::string_view title)
{
  const std::string copy(title);
  [ns_window setTitle:[NSString stringWithUTF8String:copy.c_str()]];
}

int cocoa_window_t::set_size(extent_t size)
{
  if ([ns_window styleMask] & NSWindowStyleMaskFullScreen)
    return errc::busy;
  NSRect frame = [ns_window frame];
  const NSRect content = [ns_window contentRectForFrameRect:frame];
  const NSRect wanted = NSMakeRect(content.origin.x, content.origin.y + content.size.height - size.height, size.width, size.height);
  frame = [ns_window frameRectForContentRect:wanted];
  [ns_window setFrame:frame display:YES];
  return 0;
}

int cocoa_window_t::set_position(point_t position)
{
  NSScreen *primary = [[NSScreen screens] firstObject];
  const double height = primary ? primary.frame.size.height : 0;
  [ns_window setFrameTopLeftPoint:NSMakePoint(position.x, height - position.y)];
  return 0;
}

std::expected<point_t, int> cocoa_window_t::position() const
{
  NSScreen *primary = [[NSScreen screens] firstObject];
  const double height = primary ? primary.frame.size.height : 0;
  const NSRect frame = [ns_window frame];
  return point_t{frame.origin.x, height - (frame.origin.y + frame.size.height)};
}

void cocoa_window_t::set_size_limits(extent_t min_size, extent_t max_size)
{
  [ns_window setContentMinSize:NSMakeSize(std::max(0, min_size.width), std::max(0, min_size.height))];
  if (max_size.width > 0 && max_size.height > 0)
    [ns_window setContentMaxSize:NSMakeSize(max_size.width, max_size.height)];
  else
    [ns_window setContentMaxSize:NSMakeSize(CGFLOAT_MAX, CGFLOAT_MAX)];
}

void cocoa_window_t::set_visible(bool visible)
{
  if (visible)
    [ns_window orderFront:nil];
  else
    [ns_window orderOut:nil];
  update_visibility();
}

void cocoa_window_t::set_fullscreen(bool fullscreen)
{
  const bool now = [ns_window styleMask] & NSWindowStyleMaskFullScreen;
  if (now != fullscreen)
    [ns_window toggleFullScreen:nil];
}

void cocoa_window_t::minimize()
{
  [ns_window miniaturize:nil];
}

void cocoa_window_t::maximize()
{
  if (![ns_window isZoomed])
    [ns_window zoom:nil];
}

void cocoa_window_t::restore()
{
  if ([ns_window isMiniaturized])
    [ns_window deminiaturize:nil];
  else if ([ns_window isZoomed])
    [ns_window zoom:nil];
}

void cocoa_window_t::focus()
{
  [NSApp activateIgnoringOtherApps:YES];
  [ns_window makeKeyAndOrderFront:nil];
}

void cocoa_window_t::set_cursor(cursor_t cursor)
{
  _cursor = cursor;
  const NSPoint at = [ns_window mouseLocationOutsideOfEventStream];
  if (NSPointInRect([view convertPoint:at fromView:nil], [view bounds]))
    apply_cursor();
}

void cocoa_window_t::frame_wanted()
{
  _clock.request();
}

void cocoa_window_t::tick(void *context)
{
  static_cast<cocoa_window_t *>(context)->window.on_frame(loop_core_t::now());
}

native_window_t cocoa_window_t::native() const
{
  return {platform_t::cocoa, nullptr, (__bridge void *)ns_window, 0, (__bridge void *)view, 0};
}

void *cocoa_metal_layer(window_impl_t &window)
{
  auto *backend = static_cast<cocoa_window_t *>(window.backend.get());
  if (!backend->metal_layer)
  {
    backend->metal_layer = [CAMetalLayer layer];
    [backend->view setWantsLayer:YES];
    [backend->view setLayer:backend->metal_layer];
    backend->report_size();
  }
  return (__bridge void *)backend->metal_layer;
}

std::expected<std::unique_ptr<display_backend_t>, int> make_cocoa_backend(display_impl_t &display)
{
  auto made = std::make_unique<cocoa_display_t>(display);
  if (int result = made->open(); result < 0)
    return std::unexpected(result);
  return made;
}

namespace
{
constexpr std::intptr_t cl_context_property_use_cgl_sharegroup_apple = 0x10000000;

void *opengl_library()
{
  static void *library = dlopen("/System/Library/Frameworks/OpenGL.framework/OpenGL", RTLD_LAZY | RTLD_LOCAL);
  return library;
}

class cgl_context_t final : public gl_impl_t
{
public:
  ~cgl_context_t() override
  {
    release();
  }

  int create(window_impl_t &window, const gl_config_t &config)
  {
    if (config.es)
      return errc::not_supported;
    auto *backend = static_cast<cocoa_window_t *>(window.backend.get());
    std::vector<NSOpenGLPixelFormatAttribute> attributes = {NSOpenGLPFADoubleBuffer, NSOpenGLPFAOpenGLProfile};
    if (config.major >= 4 && config.core_profile)
      attributes.push_back(NSOpenGLProfileVersion4_1Core);
    else if (config.major >= 3 && config.core_profile)
      attributes.push_back(NSOpenGLProfileVersion3_2Core);
    else
      attributes.push_back(NSOpenGLProfileVersionLegacy);
    attributes.insert(attributes.end(), {NSOpenGLPFAColorSize, 24, NSOpenGLPFAAlphaSize, static_cast<NSOpenGLPixelFormatAttribute>(config.transparent ? 8 : 0), NSOpenGLPFADepthSize, static_cast<NSOpenGLPixelFormatAttribute>(config.depth_bits), NSOpenGLPFAStencilSize, static_cast<NSOpenGLPixelFormatAttribute>(config.stencil_bits)});
    if (config.samples > 0)
      attributes.insert(attributes.end(), {NSOpenGLPFAMultisample, NSOpenGLPFASampleBuffers, 1, NSOpenGLPFASamples, static_cast<NSOpenGLPixelFormatAttribute>(config.samples)});
    attributes.push_back(0);
    NSOpenGLPixelFormat *format = [[NSOpenGLPixelFormat alloc] initWithAttributes:attributes.data()];
    if (!format)
      return errc::not_supported;
    _context = [[NSOpenGLContext alloc] initWithFormat:format shareContext:nil];
    if (!_context)
      return errc::not_supported;
    [backend->view setWantsBestResolutionOpenGLSurface:YES];
    if (config.transparent)
    {
      GLint opaque = 0;
      [_context setValues:&opaque forParameter:NSOpenGLContextParameterSurfaceOpacity];
    }
    [_context setView:backend->view];
    _window = &window;
    _framebuffer = window.framebuffer;
    window.attach(*this);
    if (int result = make_current(); result < 0)
      return result;
    set_swap_interval(config.vsync ? 1 : 0);
    return 0;
  }

  int make_current() override
  {
    if (!_context)
      return errc::canceled;
    if (_window && _window->framebuffer != _framebuffer)
    {
      _framebuffer = _window->framebuffer;
      [_context update];
    }
    [_context makeCurrentContext];
    return 0;
  }

  void release_current() override
  {
    if (_context && [NSOpenGLContext currentContext] == _context)
      [NSOpenGLContext clearCurrentContext];
  }

  int swap_buffers() override
  {
    if (!_context)
      return errc::canceled;
    [_context flushBuffer];
    return 0;
  }

  void *proc_address(const char *name) const override
  {
    void *library = opengl_library();
    return library ? dlsym(library, name) : nullptr;
  }

  int set_swap_interval(int interval) override
  {
    if (!_context)
      return errc::canceled;
    GLint value = interval;
    [_context setValues:&value forParameter:NSOpenGLContextParameterSwapInterval];
    return 0;
  }

  gl_native_t native() const override
  {
    return {nullptr, (__bridge void *)_context, _context ? [_context CGLContextObj] : nullptr, nullptr};
  }

  std::vector<std::intptr_t> opencl_properties() const override
  {
    if (!_context)
      return {};
    CGLShareGroupObj group = CGLGetShareGroup([_context CGLContextObj]);
    return {cl_context_property_use_cgl_sharegroup_apple, reinterpret_cast<std::intptr_t>(group)};
  }

  void window_closing() noexcept override
  {
    release();
  }

private:
  void release() noexcept
  {
    if (!_context)
      return;
    if ([NSOpenGLContext currentContext] == _context)
      [NSOpenGLContext clearCurrentContext];
    [_context clearDrawable];
    _context = nil;
    _window = nullptr;
  }

  NSOpenGLContext *_context = nil;
  window_impl_t *_window = nullptr;
  extent_t _framebuffer;
};
} // namespace

std::expected<std::unique_ptr<gl_impl_t>, int> make_cgl_context(window_impl_t &window, const gl_config_t &config)
{
  auto context = std::make_unique<cgl_context_t>();
  if (int result = context->create(window, config); result < 0)
    return std::unexpected(result);
  return context;
}
} // namespace vio::gui::detail

namespace vio::gui::metal
{
std::expected<void *, error_t> create_layer(window_t &window)
{
  if (!window)
    return std::unexpected(make_error(errc::canceled));
  return detail::cocoa_metal_layer(*window.impl());
}
} // namespace vio::gui::metal

using vio::gui::button_t;
using vio::gui::focus_event_t;
using vio::gui::key_event_t;
using vio::gui::modifier_t;
using vio::gui::point_t;
using vio::gui::pointer_button_event_t;
using vio::gui::pointer_enter_event_t;
using vio::gui::pointer_move_event_t;
using vio::gui::scroll_event_t;
using vio::gui::text_event_t;

@implementation VioView

- (BOOL)acceptsFirstResponder
{
  return YES;
}

- (BOOL)acceptsFirstMouse:(NSEvent *)event
{
  return YES;
}

- (BOOL)isOpaque
{
  return YES;
}

- (BOOL)wantsUpdateLayer
{
  return YES;
}

- (void)updateTrackingAreas
{
  if (tracking)
    [self removeTrackingArea:tracking];
  tracking = [[NSTrackingArea alloc] initWithRect:[self bounds] options:NSTrackingMouseEnteredAndExited | NSTrackingActiveInKeyWindow | NSTrackingCursorUpdate | NSTrackingInVisibleRect | NSTrackingEnabledDuringMouseDrag owner:self userInfo:nil];
  [self addTrackingArea:tracking];
  [super updateTrackingAreas];
}

- (point_t)pointFor:(NSEvent *)event
{
  const NSPoint at = [self convertPoint:[event locationInWindow] fromView:nil];
  return point_t{at.x, [self bounds].size.height - at.y};
}

- (void)setFrameSize:(NSSize)size
{
  [super setFrameSize:size];
  if (owner)
  {
    owner->report_size();
    owner->live_resize();
  }
}

- (void)drawRect:(NSRect)rect
{
  if (owner)
    owner->window.on_damage();
}

- (void)updateLayer
{
  if (owner)
    owner->window.on_damage();
}

- (void)viewDidChangeBackingProperties
{
  [super viewDidChangeBackingProperties];
  if (owner)
    owner->report_size();
}

- (void)cursorUpdate:(NSEvent *)event
{
  if (owner)
    owner->apply_cursor();
}

- (void)mouseEntered:(NSEvent *)event
{
  if (!owner)
    return;
  owner->apply_cursor();
  owner->window.on_input(pointer_enter_event_t{true, [self pointFor:event]});
}

- (void)mouseExited:(NSEvent *)event
{
  if (!owner)
    return;
  owner->cursor_left();
  owner->window.on_input(pointer_enter_event_t{false, [self pointFor:event]});
}

- (void)mouseMoved:(NSEvent *)event
{
  if (owner)
    owner->window.on_input(pointer_move_event_t{[self pointFor:event], vio::gui::detail::translate_flags([event modifierFlags])});
}

- (void)mouseDragged:(NSEvent *)event
{
  [self mouseMoved:event];
}

- (void)rightMouseDragged:(NSEvent *)event
{
  [self mouseMoved:event];
}

- (void)otherMouseDragged:(NSEvent *)event
{
  [self mouseMoved:event];
}

- (void)button:(button_t)button pressed:(bool)pressed event:(NSEvent *)event
{
  if (owner)
    owner->window.on_input(pointer_button_event_t{button, pressed, [self pointFor:event], vio::gui::detail::translate_flags([event modifierFlags])});
}

- (button_t)otherButton:(NSEvent *)event
{
  switch ([event buttonNumber])
  {
  case 2: return button_t::middle;
  case 3: return button_t::back;
  case 4: return button_t::forward;
  default: return button_t::other;
  }
}

- (void)mouseDown:(NSEvent *)event
{
  [self button:button_t::left pressed:true event:event];
}

- (void)mouseUp:(NSEvent *)event
{
  [self button:button_t::left pressed:false event:event];
}

- (void)rightMouseDown:(NSEvent *)event
{
  [self button:button_t::right pressed:true event:event];
}

- (void)rightMouseUp:(NSEvent *)event
{
  [self button:button_t::right pressed:false event:event];
}

- (void)otherMouseDown:(NSEvent *)event
{
  [self button:[self otherButton:event] pressed:true event:event];
}

- (void)otherMouseUp:(NSEvent *)event
{
  [self button:[self otherButton:event] pressed:false event:event];
}

- (void)scrollWheel:(NSEvent *)event
{
  if (!owner)
    return;
  double dx = [event scrollingDeltaX];
  double dy = [event scrollingDeltaY];
  if ([event hasPreciseScrollingDeltas])
  {
    dx *= 0.1;
    dy *= 0.1;
  }
  if (dx != 0 || dy != 0)
    owner->window.on_input(scroll_event_t{dx, dy, [self pointFor:event], vio::gui::detail::translate_flags([event modifierFlags])});
}

- (void)keyDown:(NSEvent *)event
{
  if (!owner)
    return;
  key_event_t key{vio::gui::detail::translate_key([event keyCode]), [event keyCode], vio::gui::detail::translate_flags([event modifierFlags]), true, static_cast<bool>([event isARepeat])};
  owner->window.on_input(key);
  NSString *characters = [event characters];
  std::string text;
  for (NSUInteger i = 0; i < [characters length]; ++i)
  {
    const unichar unit = [characters characterAtIndex:i];
    if (unit < 0x20 || unit == 0x7f || (unit >= 0xf700 && unit <= 0xf8ff))
      return;
  }
  if ([characters length] > 0)
    text = [characters UTF8String];
  if (!text.empty() && !([event modifierFlags] & NSEventModifierFlagCommand))
    owner->window.on_input(text_event_t{std::move(text)});
}

- (void)keyUp:(NSEvent *)event
{
  if (!owner)
    return;
  key_event_t key{vio::gui::detail::translate_key([event keyCode]), [event keyCode], vio::gui::detail::translate_flags([event modifierFlags]), false, false};
  owner->window.on_input(key);
}

- (void)flagsChanged:(NSEvent *)event
{
  if (!owner)
    return;
  const auto key = vio::gui::detail::translate_key([event keyCode]);
  const NSEventModifierFlags flag = vio::gui::detail::flag_for(key);
  if (!flag)
    return;
  const bool pressed = ([event modifierFlags] & flag) != 0;
  owner->window.on_input(key_event_t{key, [event keyCode], vio::gui::detail::translate_flags([event modifierFlags]), pressed, false});
}

@end

@implementation VioWindowDelegate

- (BOOL)windowShouldClose:(NSWindow *)sender
{
  if (owner)
    owner->window.on_close_request();
  return NO;
}

- (void)windowDidResize:(NSNotification *)notification
{
  if (owner)
    owner->report_size();
}

- (void)windowDidChangeBackingProperties:(NSNotification *)notification
{
  if (owner)
    owner->report_size();
}

- (void)windowDidMiniaturize:(NSNotification *)notification
{
  if (owner)
    owner->update_visibility();
}

- (void)windowDidDeminiaturize:(NSNotification *)notification
{
  if (owner)
    owner->update_visibility();
}

- (void)windowDidChangeOcclusionState:(NSNotification *)notification
{
  if (!owner)
    return;
  owner->occluded = !([owner->ns_window occlusionState] & NSWindowOcclusionStateVisible);
  owner->update_visibility();
}

- (void)windowDidBecomeKey:(NSNotification *)notification
{
  if (owner)
    owner->window.on_input(focus_event_t{true});
}

- (void)windowDidResignKey:(NSNotification *)notification
{
  if (owner)
    owner->window.on_input(focus_event_t{false});
}

@end
