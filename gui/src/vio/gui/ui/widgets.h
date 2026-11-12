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

#pragma once

// The first widgets (G46): a button, a checkbox and a combobox. Each is an ordinary component --
// nothing here reaches past what ui.h offers any program -- so they are also the worked example of
// how to write one.
//
// They are controlled: the value lives in the parent and comes down as props; a change comes up as
// an event, which the parent applies to its own state. The parent's view mounts the widget with the
// value it holds, so the parent is the one place the value is, and setting it from code is
// assigning a member:
//
//   struct settings_t
//   {
//     bool notify = true;
//     ui::checkbox_t notify_box;
//
//     ui::node_t view() const
//     {
//       return ui::mount(notify_box, {.label = "Notify me", .checked = notify});
//     }
//     ui::behaviour_t behave(ui::scope_t &scope)
//     {
//       auto changes = ui::subscribe<ui::toggle_event_t>(notify_box.changed);
//       while (auto change = co_await changes)
//         notify = change->checked;
//     }
//   };
//
// What a widget keeps itself is only what no parent cares about: whether a menu is open, which row
// the keyboard is on.

#include <cstddef>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "vio/gui/ui/ui.h"

namespace vio::gui::ui
{
class checkbox_t;
class combobox_t;

// Colours and sizes every widget draws with. One dark theme for now; making it a prop, or something
// a subtree inherits, is open.
struct theme_t
{
  color_t text{0.92f, 0.92f, 0.94f, 1};
  color_t text_disabled{0.5f, 0.5f, 0.53f, 1};
  color_t control{0.22f, 0.22f, 0.25f, 1};
  color_t control_hovered{0.27f, 0.27f, 0.31f, 1};
  color_t control_held{0.17f, 0.17f, 0.19f, 1};
  color_t control_disabled{0.18f, 0.18f, 0.2f, 1};
  color_t border{0.36f, 0.36f, 0.4f, 1};
  color_t border_hovered{0.5f, 0.5f, 0.56f, 1};
  color_t accent{0.24f, 0.5f, 0.95f, 1};
  color_t accent_hovered{0.33f, 0.58f, 1.0f, 1};
  color_t accent_held{0.18f, 0.4f, 0.8f, 1};
  color_t focus_ring{0.55f, 0.75f, 1.0f, 1};
  color_t menu{0.2f, 0.2f, 0.23f, 1};
  float text_size = 14;
  float radius = 6;
};

[[nodiscard]] const theme_t &theme() noexcept;

// A push button. Subscribe to its `press`: `ui::subscribe<ui::press_event_t>(save.press)`. Takes
// focus; Space presses it.
class button_t
{
public:
  struct props_t
  {
    std::string label;
    // The accent colour: the button a dialog expects.
    bool primary = false;
    bool enabled = true;
    friend bool operator==(const props_t &, const props_t &) = default;
  };
  props_t props;
  pressable_t press{focusable};

  [[nodiscard]] node_t view() const;
};

struct toggle_event_t
{
  const checkbox_t *source = nullptr;
  bool checked = false;
};

// A box that is ticked or not, with a label beside it; the label is part of what is pressed. It
// asks for the opposite of what it was given through `changed`.
class checkbox_t
{
public:
  struct props_t
  {
    std::string label;
    bool checked = false;
    bool enabled = true;
    friend bool operator==(const props_t &, const props_t &) = default;
  };
  props_t props;
  event_source_t<toggle_event_t> changed;

  [[nodiscard]] node_t view() const;
  behaviour_t behave(scope_t &scope);

private:
  pressable_t _press{focusable};
  // What it last asked for, until its next view: two presses in one turn both see the props of
  // the frame before, so the second must ask from what the first asked, not from those.
  mutable std::optional<bool> _asked;
};

struct select_event_t
{
  const combobox_t *source = nullptr;
  std::size_t index = 0;
};

namespace detail
{
// A combobox's open list: a popup component the combobox creates when it opens and drops when it
// closes. Its rows are fixed when it is made, so a deque, whose elements never move.
class menu_t
{
public:
  struct props_t
  {
    std::vector<std::string> options;
    int selected = -1;
    // The row the keyboard is on.
    int highlight = -1;
    // Not shown, but as wide as it is: the combobox's placeholder, so menu and field match.
    std::string widest;
    friend bool operator==(const props_t &, const props_t &) = default;
  };
  explicit menu_t(std::size_t rows);

  props_t props;
  std::deque<pressable_t> rows;

  [[nodiscard]] node_t view() const;
};
} // namespace detail

// One of a list of strings, picked from a menu that opens under it. As wide as its widest option,
// so it does not change size as the choice does. Keyboard: Space, Enter or Alt+Down open it; Up and
// Down move through the options, open or closed; Enter or Space picks; Escape and Tab close. A
// press outside the open menu closes it and goes no further.
class combobox_t
{
public:
  struct props_t
  {
    std::vector<std::string> options;
    // -1 for none, which shows `placeholder`.
    int selected = -1;
    std::string placeholder;
    bool enabled = true;
    friend bool operator==(const props_t &, const props_t &) = default;
  };
  props_t props;
  event_source_t<select_event_t> changed;

  [[nodiscard]] node_t view() const;
  behaviour_t behave(scope_t &scope);

  [[nodiscard]] bool open() const noexcept
  {
    return bool(_menu);
  }

private:
  void pick(std::size_t index, scope_t &scope);
  // The choice as far as this widget knows: what it last asked for this frame, else its props.
  [[nodiscard]] int current() const noexcept
  {
    return _asked.value_or(props.selected);
  }

  pressable_t _field{focusable};
  pressable_t _dismiss;
  std::shared_ptr<detail::menu_t> _menu;
  int _highlight = -1;
  mutable std::optional<int> _asked;
};
} // namespace vio::gui::ui
