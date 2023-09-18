
from typing import Optional

from binaryninja import BinaryView, Function
from binaryninjaui import DockContextHandler, getMonospaceFont

import binaryninjaui
if "qt_major_version" in dir(binaryninjaui) and binaryninjaui.qt_major_version == 6:
    from PySide6.QtWidgets import QPlainTextEdit, QVBoxLayout, QFormLayout, QLabel, QWidget
    from PySide6.QtGui import QFontMetrics
else:
    from PySide2.QtWidgets import QPlainTextEdit, QVBoxLayout, QFormLayout, QLabel, QWidget
    from PySide2.QtGui import QFontMetrics

from .core import AriadneCore
from .util_funcs import log_info, func_name

class AriadneFuncWidget(QWidget, DockContextHandler):
    """
    Shows dynamic graphs in a widget
    """

    # The currently focused BinaryView.
    bv: Optional[BinaryView] = None

    def __init__(self, parent: QWidget, name: str, bv: Optional[BinaryView], core: AriadneCore):
        """
        Initialize a new AriadneGraphWidget.

        :param parent: the QWidget to parent this NotepadDockWidget to
        :param name: the name to register the dock widget under
        :param bv: the currently focused BinaryView (may be None)
        """

        self.bv = bv
        self.core = core
        self.locked = False
        self.current_function = None
        self.metadata_loaded = False

        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        header_layout = QFormLayout()
        self.function_info = QLabel("")
        header_layout.addRow(self.tr("Function:"), self.function_info)

        textbox_layout = QVBoxLayout()
        self.textbox = QPlainTextEdit()
        self.textbox.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.textbox.setReadOnly(True)
        # getMonospaceFont from binaryninjaui
        font = getMonospaceFont(self)
        self.textbox.setFont(font)
        font = QFontMetrics(font)
        #self.textbox.setMinimumWidth(40 * font.averageCharWidth())
        #self.textbox.setMinimumHeight(25 * font.lineSpacing())

        textbox_layout.addWidget(self.textbox, 0)

        layout =  QVBoxLayout()
        layout.addLayout(header_layout)
        layout.addLayout(textbox_layout)
        #layout.setcontentsmargins(0, 0, 0, 0)
        self.setLayout(layout)

    def set_textbox(self, text: str):
        self.textbox.setPlainText(text)

    def add_transition(self, new_function: Function):
        function_metadata = self.core.get_function_metadata(new_function)
        # Placeholder metadata will just be a short message about metadata being
        # queued or not, but should only be a few lines, real metadata is more
        if len(function_metadata.split('\n')) > 5:
            self.metadata_loaded = True
        self.set_textbox(function_metadata)

    def update_current_function(self, function: Function):
        function_name = func_name(function)
        function_start = function.start
        self.function_info.setText(f'{function_name} @ 0x{function_start:x}')
        if function != self.current_function:
            # If the target doesn't have this function, this will return false
            self.core.add_function_transition(function)
            self.add_transition(function)
        # If metadata wasn't loaded and we're still on the same function,
        # check on each click
        elif self.metadata_loaded is False:
            self.add_transition(function)
        self.current_function = function

    def notifyOffsetChanged(self, offset: int):
        if self.bv is None:
            return
        if not self.locked:
            current_function_list = self.bv.get_functions_containing(offset)
            if current_function_list:
                current_function = current_function_list[0]
                self.update_current_function(current_function)
                if len(current_function_list) > 1:
                    log_info(f'More than one function contains 0x{offset:x}, ' +
                             f'picked {func_name(current_function)}')

    def shouldBeVisible(self, view_frame):
        return view_frame is not None

    def notifyViewChanged(self, view_frame):
        if view_frame is None:
            pass
        else:
            new_bv = view_frame.getCurrentViewInterface().getData()
            # No need for any special handling when the BV changes
            self.bv = new_bv
