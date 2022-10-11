from .core import AriadneCore
import traceback
from typing import Any

from binaryninja import core_ui_enabled

from binaryninjaui import DockHandler

from PySide6.QtWidgets import QWidget
from PySide6.QtCore import Qt


# Keep a collection of all of our registered dock widgets.
_dock_widgets = []


def _create_widget(widget_class, name, parent, data, core):
    """Create a widget and add it to the internal widget list."""

    global _dock_widgets

    try:
        w = widget_class(parent, name, data, core)

        # Raise an exception if widget creation failed.
        if not w:
            raise Exception("Widget creation failed. Bad widget class?")

        # Search for any existing widgets with the same name.
        found = False
        for (bv, widgets) in _dock_widgets:
            if bv == data:
                widgets[name] = w
                found = True

        if not found:
            _dock_widgets.append((data, {name: w}))

        w.destroyed.connect(lambda destroyed: _destroy_widget(destroyed, w, data, name))

        return w

    # Return a dummy widget and print the exception if something went wrong.
    except Exception as e:
        traceback.print_exc(e)
        return QWidget(parent)


def _destroy_widget(_destroyed, old, data, _name):
    """Destroys a widget if there are no remaining references to it."""

    for (bv, widgets) in _dock_widgets:
        if bv == data:
            for (name, widget) in widgets.items():
                if widget == old:
                    widgets.pop(name)
                    return


def register_widget(
    widget_class: Any,
    name: str,
    area: Qt.DockWidgetArea,
    orientation: Qt.Orientation,
    default_visibility: bool,
    core: AriadneCore,
):
    """
    Register a dock widget.

    :param widget_class: the class of the widget to instantiate
    :param name: the name for the widget (will appear in menus)
    :param area: where the widget should be docker
    :param orientation: the orientation of the widget
    :param default_visibility: whether the widget be visible by default
    """

    dock_handler = DockHandler.getActiveDockHandler()
    dock_handler.addDockWidget(
        name,
        lambda n, p, d: _create_widget(widget_class, n, p, d, core),
        area,
        orientation,
        default_visibility,
    )
