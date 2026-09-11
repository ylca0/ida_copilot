"""IDA Copilot - IDA Pro 9.x plugin entry point.

Registers a plugin that appears in IDA's ``Edit > Plugins`` menu with the
``Ctrl+Shift+C`` hotkey. The chat window docks to the right half of the
workspace.
"""

from __future__ import annotations

import ida_idaapi

from ida_copilot.ui import ChatWidget, SettingsDialog, WINDOW_TITLE


class CopilotPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX
    comment = "IDA Copilot - AI assistant with Pydantic AI"
    help = "Open the chat window (Ctrl+Shift+C), configure an OpenAI-compatible endpoint, and let the agent drive IDA."
    wanted_name = "IDA Copilot"
    wanted_hotkey = "Ctrl-Shift-C"

    def init(self):
        self.form = None
        self.widget = None
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        # Hotkey / Plugins menu both funnel here.
        self.open_window()

    def open_window(self):
        if self.form is not None and self.widget is not None:
            # Already open - bring to front.
            try:
                import ida_kernwin

                ida_kernwin.activate_widget(self.form.GetWidget(), True)
            except Exception:
                pass
            return

        from PyQt5 import QtWidgets
        import ida_kernwin

        class ChatForm(ida_kernwin.PluginForm):
            def __init__(self):
                super().__init__()
                self.chat: ChatWidget = None

            def OnCreate(self, form):
                parent = self.FormToPyQtWidget(form)
                self.chat = ChatWidget(parent)
                layout = QtWidgets.QVBoxLayout(parent)
                layout.setContentsMargins(0, 0, 0, 0)
                layout.setSpacing(0)
                layout.addWidget(self.chat)
                self.chat.settingsRequested.connect(lambda: _open_settings(self.chat))

            def OnClose(self, form):
                if self.chat is not None:
                    self.chat.shutdown()

        self.form = ChatForm()
        # Dock to the right half of the workspace by default.
        self.form.Show(
            WINDOW_TITLE,
            options=ida_kernwin.PluginForm.WOPN_DP_RIGHT | ida_kernwin.PluginForm.WOPN_RESTORE,
        )
        self.widget = self.form.GetWidget()

    def term(self):
        if self.form is not None:
            try:
                self.form.OnClose(self.form.GetWidget())
            except Exception:
                pass
            try:
                self.form.Close(0)
            except Exception:
                pass
            self.form = None
        self.widget = None


def _open_settings(chat: ChatWidget):
    dlg = SettingsDialog(chat.settings)
    if dlg.exec_():
        new = dlg.result_settings()
        if new is not None:
            chat.apply_settings(new)


def PLUGIN_ENTRY():
    return CopilotPlugin()
