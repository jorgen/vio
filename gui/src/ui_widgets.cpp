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

#include "vio/gui/ui/widgets.h"

#include <algorithm>

namespace vio::gui::ui
{
namespace
{
constexpr color_t clear{0, 0, 0, 0};
constexpr color_t white{1, 1, 1, 1};

// A tick, as one closed outline in the unit square.
std::shared_ptr<const path_t> check_icon()
{
  static const auto path = []
  {
    auto p = std::make_shared<path_t>();
    p->move_to(0.12f, 0.53f).line_to(0.23f, 0.42f).line_to(0.40f, 0.59f).line_to(0.77f, 0.22f).line_to(0.88f, 0.33f).line_to(0.40f, 0.81f).close();
    return std::shared_ptr<const path_t>(std::move(p));
  }();
  return path;
}

// A chevron pointing down.
std::shared_ptr<const path_t> chevron_icon()
{
  static const auto path = []
  {
    auto p = std::make_shared<path_t>();
    p->move_to(0.14f, 0.36f).line_to(0.25f, 0.25f).line_to(0.5f, 0.5f).line_to(0.75f, 0.25f).line_to(0.86f, 0.36f).line_to(0.5f, 0.72f).close();
    return std::shared_ptr<const path_t>(std::move(p));
  }();
  return path;
}

event_ref_t events_if(bool enabled, const pressable_t &source)
{
  return enabled ? event_ref_t(source) : event_ref_t{};
}

// A control's fill for what the pointer is doing to it.
color_t control_color(const theme_t &t, bool enabled, const pressable_t &source)
{
  if (!enabled)
    return t.control_disabled;
  if (source.held())
    return t.control_held;
  return source.hovered() ? t.control_hovered : t.control;
}

color_t accent_color(const theme_t &t, const pressable_t &source)
{
  if (source.held())
    return t.accent_held;
  return source.hovered() ? t.accent_hovered : t.accent;
}
} // namespace

const theme_t &theme() noexcept
{
  static const theme_t dark;
  return dark;
}

// ---- button

node_t button_t::view() const
{
  const auto &t = theme();
  const bool on = props.enabled;
  const bool ring = on && press.focus_visible();
  color_t fill = control_color(t, on, press);
  if (on && props.primary)
    fill = accent_color(t, press);
  return box_t{.size = {72, 32},
               .color = fill,
               .radius = t.radius,
               .border_width = ring ? 2.0f : (props.primary && on ? 0.0f : 1.0f),
               .border_color = ring ? t.focus_ring : (press.hovered() && on ? t.border_hovered : t.border),
               .shadow = on ? shadow_t{.x = 0, .y = 1, .blur = 1.5f, .color = {0, 0, 0, 0.35f}} : shadow_t{},
               .events = events_if(on, press),
               .padding = {14, 0},
               .children = {text_t{.text = props.label, .size = t.text_size, .color = !on ? t.text_disabled : (props.primary ? white : t.text)}}};
}

// ---- checkbox

node_t checkbox_t::view() const
{
  // The parent has answered what was asked by now: these props are its answer.
  _asked.reset();
  const auto &t = theme();
  const bool on = props.enabled;
  const bool ring = on && _press.focus_visible();
  color_t fill = control_color(t, on, _press);
  if (props.checked)
    fill = on ? accent_color(t, _press) : t.border;
  box_t square{.size = {18, 18}, .color = fill, .radius = 4, .border_width = ring ? 2.0f : (props.checked ? 0.0f : 1.5f), .border_color = ring ? t.focus_ring : (_press.hovered() && on ? t.border_hovered : t.border)};
  if (props.checked)
    square.children.push_back(icon_t{.path = check_icon(), .size = 14, .color = on ? white : t.control_disabled});
  // The whole of it, label included, is what is pressed.
  return box_t{.color = clear,
               .events = events_if(on, _press),
               .padding = {0, 3},
               .children = {row_t{.gap = 8, .align = align_t::center, .children = {std::move(square), text_t{.text = props.label, .size = t.text_size, .color = on ? t.text : t.text_disabled}}}}};
}

behaviour_t checkbox_t::behave(scope_t &scope)
{
  auto presses = subscribe<press_event_t>(_press);
  while (co_await presses)
  {
    _asked = !_asked.value_or(props.checked);
    emit(changed, toggle_event_t{this, *_asked}, scope);
  }
}

// ---- combobox

namespace detail
{
menu_t::menu_t(std::size_t count)
  : rows(count)
{
}

node_t menu_t::view() const
{
  const auto &t = theme();
  const auto n = std::min(rows.size(), props.options.size());
  // Two marks, kept apart: the keyboard's row is lit in the accent, and is what Enter picks; the
  // row under the pointer is only tinted. Letting the pointer move the keyboard's row made a pointer
  // resting where the menu opened take the arrow keys over.
  column_t list{.align = align_t::stretch};
  for (std::size_t i = 0; i < n; ++i)
  {
    const bool lit = int(i) == props.highlight;
    const bool chosen = int(i) == props.selected;
    // Padding, text, at least 8 of space and a 12-wide tick: as wide as the field over it, whose
    // padding, gap and chevron add up to the same.
    node_t mark = chosen ? node_t(icon_t{.path = check_icon(), .size = 12, .color = lit ? white : t.accent}) : node_t(spacer_t{.grow = 0, .size = {12, 12}});
    list.children.push_back(
      box_t{.color = lit ? t.accent : (rows[i].hovered() ? t.control_hovered : clear),
            .events = rows[i],
            .padding = {9, 5, 7, 5},
            .align_x = align_t::stretch,
            .children = {row_t{.align = align_t::center, .children = {text_t{.text = props.options[i], .size = t.text_size, .color = lit ? white : t.text}, spacer_t{.grow = 1, .size = {8, 0}}, std::move(mark)}}}});
  }
  box_t panel{.color = t.menu,
              .radius = t.radius,
              .border_width = 1,
              .border_color = t.border,
              .shadow = {.x = 0, .y = 4, .blur = 10, .color = {0, 0, 0, 0.5f}},
              .padding = {1, 4},
              .align_x = align_t::stretch,
              .children = {std::move(list)}};
  // Overlapping the rows, unseen, so the menu is at least as wide as the field's placeholder.
  if (!props.widest.empty())
    panel.children.push_back(box_t{.color = clear, .padding = {9, 0, 27, 0}, .children = {text_t{.text = props.widest, .size = t.text_size, .color = clear}}});
  // A little air between the field and the menu.
  return box_t{.color = clear, .padding = {0, 4, 0, 0}, .children = {std::move(panel)}};
}
} // namespace detail

node_t combobox_t::view() const
{
  _asked.reset();
  const auto &t = theme();
  const bool on = props.enabled;
  const bool ring = on && _field.focus_visible();
  const bool has_choice = props.selected >= 0 && std::size_t(props.selected) < props.options.size();

  // Every option, invisible, under the one shown: the field is as wide as the widest of them and
  // keeps that width whichever is chosen.
  box_t texts{.color = clear, .align_x = align_t::start};
  for (const auto &option : props.options)
    texts.children.push_back(text_t{.text = option, .size = t.text_size, .color = clear});
  if (!props.placeholder.empty())
    texts.children.push_back(text_t{.text = props.placeholder, .size = t.text_size, .color = clear});
  if (has_choice)
    texts.children.push_back(text_t{.text = props.options[std::size_t(props.selected)], .size = t.text_size, .color = on ? t.text : t.text_disabled});
  else
    texts.children.push_back(text_t{.text = props.placeholder, .size = t.text_size, .color = t.text_disabled});

  color_t fill = control_color(t, on, _field);
  if (on && _menu && !_field.held())
    fill = t.control_hovered;
  box_t field{.size = {0, 32},
              .color = fill,
              .radius = t.radius,
              .border_width = ring ? 2.0f : 1.0f,
              .border_color = ring ? t.focus_ring : ((_field.hovered() || _menu) && on ? t.border_hovered : t.border),
              .events = events_if(on, _field),
              .padding = {10, 0, 8, 0},
              .align_x = align_t::start,
              .children = {row_t{.gap = 8, .align = align_t::center, .children = {std::move(texts), icon_t{.path = chevron_icon(), .size = 12, .color = on ? t.text : t.text_disabled}}}}};

  column_t whole{.children = {std::move(field)}};
  if (_menu)
    whole.children.push_back(mount(_menu, detail::menu_t::props_t{.options = props.options, .selected = props.selected, .highlight = _highlight, .widest = props.placeholder}).on_top(_dismiss));
  return whole;
}

void combobox_t::pick(std::size_t index, scope_t &scope)
{
  _menu.reset();
  if (index < props.options.size() && int(index) != current())
  {
    _asked = int(index);
    emit(changed, select_event_t{this, index}, scope);
  }
}

behaviour_t combobox_t::behave(scope_t &scope)
{
  auto presses = subscribe<press_event_t>(_field, _dismiss);
  auto keys = subscribe<key_event_t>(_field);
  const auto count = [this] { return int(props.options.size()); };
  const auto open_menu = [this]
  {
    _menu = std::make_shared<detail::menu_t>(props.options.size());
    _highlight = std::max(current(), 0);
  };

  while (true)
  {
    // Closed: a press opens it, and Up and Down change the choice without opening it.
    if (!_menu)
    {
      auto events = merge(scope, presses, keys);
      auto event = co_await events;
      if (!event)
        co_return;
      if (!props.enabled || count() == 0)
        continue;
      if (event->index() == 0)
      {
        if (std::get<0>(*event).source == &_field)
          open_menu();
        continue;
      }
      const auto &key = std::get<1>(*event);
      if (!key.pressed)
        continue;
      const int last = count() - 1;
      if ((key.key == key_t::down && has(key.modifiers, modifier_t::alt)) || key.key == key_t::enter || key.key == key_t::keypad_enter)
        open_menu();
      else if (key.key == key_t::down)
        pick(std::size_t(std::min(current() + 1, last)), scope);
      else if (key.key == key_t::up)
        pick(std::size_t(std::max(current() - 1, 0)), scope);
      else if (key.key == key_t::home)
        pick(0, scope);
      else if (key.key == key_t::end)
        pick(std::size_t(last), scope);
      continue;
    }

    // Open: the rows join in, for as long as this menu lasts.
    auto rows = subscribe<press_event_t>(_menu->rows);
    auto events = merge(scope, presses, keys, rows);
    while (_menu)
    {
      auto event = co_await events;
      if (!event)
        co_return;
      if (event->index() == 0)
      {
        // Space on the field picks what is lit; a press outside closes it.
        if (std::get<0>(*event).source == &_field)
          pick(std::size_t(_highlight), scope);
        else
          _menu.reset();
      }
      else if (event->index() == 1)
      {
        const auto &key = std::get<1>(*event);
        if (!key.pressed)
          continue;
        const int last = count() - 1;
        const int from = _highlight;
        if (key.key == key_t::down)
          _highlight = std::min(from + 1, last);
        else if (key.key == key_t::up)
          _highlight = std::max(from - 1, 0);
        else if (key.key == key_t::home)
          _highlight = 0;
        else if (key.key == key_t::end)
          _highlight = last;
        else if (key.key == key_t::enter || key.key == key_t::keypad_enter)
          pick(std::size_t(from), scope);
        else if (key.key == key_t::escape || key.key == key_t::tab)
          _menu.reset();
      }
      else
      {
        const auto *row = std::get<2>(*event).source;
        for (std::size_t i = 0; i < _menu->rows.size(); ++i)
        {
          if (&_menu->rows[i] == row)
          {
            pick(i, scope);
            break;
          }
        }
      }
    }
  }
}
} // namespace vio::gui::ui
