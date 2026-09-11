"""Qt chat window for IDA Copilot.

Implements the dockable widget described in the README:

* Top bar: ``Setting`` and ``New Chat`` buttons.
* Middle: message list rendering user / model / system / tool / thinking items.
* Bottom: multi-line input + ``Send``/``Stop`` button.

All interaction with the agent worker is marshalled through a ``QObject``
signal bridge so IDA's UI thread is never blocked by network I/O.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from PyQt5 import QtCore, QtGui, QtWidgets

from .agent import AgentRunner, StreamEvents
from .config import ConfigStore, Settings

WINDOW_TITLE = "IDA Copilot"
_ACTION_NAME = "ida_copilot:open_window"


# ---------------------------------------------------------------------------
# Signal bridge: worker thread -> UI thread
# ---------------------------------------------------------------------------


class _BridgeSignals(QtCore.QObject):
    part_start = QtCore.pyqtSignal(int, str)
    text_delta = QtCore.pyqtSignal(int, str)
    thinking_delta = QtCore.pyqtSignal(int, str)
    tool_start = QtCore.pyqtSignal(int, str, str)
    tool_delta = QtCore.pyqtSignal(int, str, str)
    tool_result = QtCore.pyqtSignal(int, str, str)
    turn_start = QtCore.pyqtSignal()
    turn_end = QtCore.pyqtSignal()
    error = QtCore.pyqtSignal(str)


# ---------------------------------------------------------------------------
# Simple markdown renderer (no external dependency)
# ---------------------------------------------------------------------------


_ESCAPE_RE = re.compile(r"[&<>]")
_CODELINE_RE = re.compile(r"^```([\w+#.-]*)\s*$")


def _escape_html(text: str) -> str:
    return _ESCAPE_RE.sub(lambda m: {"&": "&amp;", "<": "&lt;", ">": "&gt;"}[m.group(0)], text)


def _inline(text: str, newlines_to_br: bool = False) -> str:
    """Apply inline markdown (bold, italic, code, links) to escaped text.

    If ``newlines_to_br`` is true, any remaining newlines (outside code spans)
    are converted to ``<br>`` after escaping, which is needed for QLabel rich
    text where plain newlines do not wrap.
    """
    # escape first
    text = _escape_html(text)
    # inline code - protect code spans so their newlines are not turned into <br>
    spans: list[str] = []

    def _keep_code(m):
        spans.append("<code>%s</code>" % m.group(1))
        return "\x00%d\x00" % (len(spans) - 1)

    text = re.sub(r"`([^`\n]+)`", _keep_code, text)
    if newlines_to_br:
        text = text.replace("\n", "<br>")

    def _restore(m):
        return spans[int(m.group(1))]

    text = re.sub(r"\x00(\d+)\x00", _restore, text)
    # bold
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    # italic
    text = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"<i>\1</i>", text)
    # links
    text = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", r'<a href="\2">\1</a>', text)
    return text


def markdown_to_html(md: str) -> str:
    """Convert a small useful subset of markdown to HTML."""
    lines = md.split("\n")
    # Trim leading/trailing blank lines so the rendered text has no stray
    # empty paragraphs at the top or bottom.
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    out: list[str] = []
    in_code = False
    code_buf: list[str] = []
    in_ul = False

    def flush_ul() -> None:
        nonlocal in_ul
        if in_ul:
            out.append("</ul>")
            in_ul = False

    def flush_code() -> None:
        nonlocal in_code
        if in_code:
            out.append('<pre class="code"><code>' + _escape_html("\n".join(code_buf)) + "</code></pre>")
            in_code = False
            code_buf.clear()

    for line in lines:
        m = _CODELINE_RE.match(line.strip())
        if m:
            if in_code:
                flush_code()
            else:
                flush_ul()
                in_code = True
            continue
        if in_code:
            code_buf.append(line)
            continue
        if not line.strip():
            flush_ul()
            # Skip standalone blank lines entirely; block transitions are
            # already separated by the closing/opening tags above.
            continue
        if re.match(r"^\s*[-*+]\s+", line):
            if not in_ul:
                out.append("<ul>")
                in_ul = True
            item = re.sub(r"^\s*[-*+]\s+", "", line)
            out.append("<li>%s</li>" % _inline(item))
            continue
        flush_ul()
        if line.startswith("#"):
            level = min(len(line) - len(line.lstrip("#")), 6)
            body = line.lstrip("#").strip()
            out.append("<h%d>%s</h%d>" % (level, _inline(body), level))
        else:
            out.append("<p>%s</p>" % _inline(line))

    flush_ul()
    flush_code()
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Chat items
# ---------------------------------------------------------------------------


class _CollapsibleBlock(QtWidgets.QFrame):
    """A titled block that can be collapsed/expanded (thinking, tool calls)."""

    def __init__(self, title: str, collapsed: bool = True, accent: str = "#616161", parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self._expanded = not collapsed
        self.setObjectName("collapsible")
        lay = QtWidgets.QVBoxLayout(self)
        lay.setContentsMargins(6, 4, 6, 4)
        lay.setSpacing(4)

        self._btn = QtWidgets.QToolButton()
        self._btn.setObjectName("collapseBtn")
        self._btn.setCheckable(True)
        self._btn.setChecked(self._expanded)
        self._btn.setToolButtonStyle(QtCore.Qt.ToolButtonTextBesideIcon)
        self._btn.setText(title)
        self._btn.setStyleSheet("QToolButton { border: none; color: %s; font-weight: bold; }" % accent)
        self._btn.clicked.connect(self._toggle)
        lay.addWidget(self._btn)

        self._body = QtWidgets.QWidget()
        self._body_lay = QtWidgets.QVBoxLayout(self._body)
        self._body_lay.setContentsMargins(4, 2, 4, 2)
        self._body_lay.setSpacing(2)
        lay.addWidget(self._body)

        self._update_arrow()
        self._body.setVisible(self._expanded)

    def _toggle(self) -> None:
        self._expanded = self._btn.isChecked()
        self._body.setVisible(self._expanded)
        self._update_arrow()

    def _update_arrow(self) -> None:
        self._btn.setArrowType(QtCore.Qt.DownArrow if self._expanded else QtCore.Qt.RightArrow)

    def setCollapsed(self, collapsed: bool) -> None:
        self._expanded = not collapsed
        self._btn.setChecked(self._expanded)
        self._body.setVisible(self._expanded)
        self._update_arrow()

    def isExpanded(self) -> bool:
        return self._expanded

    def body(self) -> QtWidgets.QLayout:
        return self._body_lay


@dataclass
class _ChatItem:
    role: str  # user | model | system | error
    text: str = ""
    widget: Optional[QtWidgets.QWidget] = None
    body_lay: Optional[QtWidgets.QLayout] = None
    parts: dict[int, dict[str, Any]] = field(default_factory=dict)  # part_id -> part state
    part_order: list[int] = field(default_factory=list)  # part ids in arrival order
    busy: bool = False


# ---------------------------------------------------------------------------
# Chat widget
# ---------------------------------------------------------------------------


class ChatWidget(QtWidgets.QWidget):
    """The main plugin window content."""

    # Signals forwarded to whoever owns us (the plugin form)
    settingsRequested = QtCore.pyqtSignal()

    def __init__(self, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self.store = ConfigStore()
        self.settings = self.store.load()
        self._items: list[_ChatItem] = []
        self._current: Optional[_ChatItem] = None

        # worker
        self._bridge = _BridgeSignals()
        self._bridge.part_start.connect(self._on_part_start)
        self._bridge.text_delta.connect(self._on_text_delta)
        self._bridge.thinking_delta.connect(self._on_thinking_delta)
        self._bridge.tool_start.connect(self._on_tool_start)
        self._bridge.tool_delta.connect(self._on_tool_delta)
        self._bridge.tool_result.connect(self._on_tool_result)
        self._bridge.turn_start.connect(self._on_turn_start)
        self._bridge.turn_end.connect(self._on_turn_end)
        self._bridge.error.connect(self._on_error)

        self._build_ui()

        self._ensure_agent()

    # -- UI construction ---------------------------------------------------

    def _build_ui(self) -> None:
        root = QtWidgets.QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(6)

        # top bar
        top = QtWidgets.QHBoxLayout()
        top.setSpacing(6)
        self._btn_setting = QtWidgets.QPushButton("\u2699 Setting")
        self._btn_setting.setFixedHeight(28)
        self._btn_setting.clicked.connect(self.settingsRequested)
        self._btn_new = QtWidgets.QPushButton("\uff0b New Chat")
        self._btn_new.setFixedHeight(28)
        self._btn_new.clicked.connect(self._on_new_chat)
        top.addWidget(self._btn_setting)
        top.addWidget(self._btn_new)
        top.addStretch(1)
        root.addLayout(top)

        # message list
        self._scroll = QtWidgets.QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self._msg_container = QtWidgets.QWidget()
        self._msg_lay = QtWidgets.QVBoxLayout(self._msg_container)
        self._msg_lay.setContentsMargins(2, 2, 2, 2)
        self._msg_lay.setSpacing(8)
        self._msg_lay.addStretch(1)
        self._scroll.setWidget(self._msg_container)
        root.addWidget(self._scroll, 1)

        # input bar
        input_row = QtWidgets.QHBoxLayout()
        input_row.setSpacing(6)
        self._input = QtWidgets.QPlainTextEdit()
        self._input.setPlaceholderText("Ask about the current IDB\u2026 (Enter to send, Shift+Enter for newline)")
        self._input.setFixedHeight(64)
        self._input.installEventFilter(self)
        self._btn_send = QtWidgets.QPushButton("Send")
        # Match the input box height so the Send/Stop button lines up cleanly.
        self._btn_send.setFixedHeight(64)
        self._btn_send.setMinimumWidth(72)
        self._btn_send.clicked.connect(self._on_send_clicked)
        input_row.addWidget(self._input, 1)
        input_row.addWidget(self._btn_send)
        root.addLayout(input_row)

        self._apply_styles()

    def _apply_styles(self) -> None:
        self.setStyleSheet(
            """
            QScrollArea { border: 1px solid #c8c8c8; border-radius: 4px; background: #ffffff; }
            QPlainTextEdit { border: 1px solid #c8c8c8; border-radius: 4px; background: #ffffff; color: #1a1a1a; font-family: Consolas, monospace; font-size: 12px; }
            QPushButton { background: #f0f0f0; color: #1a1a1a; border: 1px solid #b0b0b0; border-radius: 4px; padding: 4px 10px; }
            QPushButton:hover { background: #e4e4e4; }
            QPushButton:disabled { color: #909090; }
            QFrame#collapsible { background: #f7f7f7; border: 1px solid #d0d0d0; border-radius: 4px; }
            QLabel[role="user"] { background: #dcebf7; border: 1px solid #a9cbe8; border-radius: 4px; padding: 6px; color: #1a1a1a; }
            QLabel[role="error"] { background: #fbe4e4; border: 1px solid #e8a0a0; border-radius: 4px; padding: 6px; color: #1a1a1a; }
            QLabel[role="bubble"] { background: #f5f5f5; border: 1px solid #d8d8d8; border-radius: 4px; padding: 6px; color: #1a1a1a; }
            QLabel[role="code"] { font-family: Consolas, monospace; color: #1a1a1a; background: #ffffff; }
            """
        )

    # -- agent -------------------------------------------------------------

    def _ensure_agent(self) -> None:
        events = StreamEvents(
            on_part_start=self._emitter("partstart"),
            on_text_delta=self._emitter("text"),
            on_thinking_delta=self._emitter("thinking"),
            on_tool_call_start=self._emitter("toolstart"),
            on_tool_call_delta=self._emitter("tooldelta"),
            on_tool_result=self._emitter("toolresult"),
            on_turn_start=self._emitter("turnstart"),
            on_turn_end=self._emitter("turnend"),
            on_error=self._emitter("error"),
        )
        self._runner = AgentRunner(self.settings, events)
        self._runner.start()

    def _emitter(self, kind: str):
        """Return an async callback that forwards a worker event to a Qt signal."""

        async def _emit(*args: Any) -> None:
            if kind == "partstart":
                self._bridge.part_start.emit(args[0], args[1])
            elif kind == "text":
                self._bridge.text_delta.emit(args[0], args[1])
            elif kind == "thinking":
                self._bridge.thinking_delta.emit(args[0], args[1])
            elif kind == "toolstart":
                self._bridge.tool_start.emit(args[0], args[1], args[2])
            elif kind == "tooldelta":
                self._bridge.tool_delta.emit(args[0], args[1], args[2])
            elif kind == "toolresult":
                self._bridge.tool_result.emit(args[0], args[1], args[2])
            elif kind == "turnstart":
                self._bridge.turn_start.emit()
            elif kind == "turnend":
                self._bridge.turn_end.emit()
            elif kind == "error":
                self._bridge.error.emit(args[0])

        return _emit

    # -- message rendering -------------------------------------------------

    def _add_item(self, item: _ChatItem) -> _ChatItem:
        self._items.append(item)
        # insert before the stretch
        self._msg_lay.insertWidget(self._msg_lay.count() - 1, item.widget)
        self._scroll_to_bottom()
        return item

    def _scroll_to_bottom(self) -> None:
        QtCore.QTimer.singleShot(0, lambda: self._scroll.verticalScrollBar().setValue(self._scroll.verticalScrollBar().maximum()))

    def add_user_message(self, text: str) -> _ChatItem:
        label = QtWidgets.QLabel()
        label.setTextFormat(QtCore.Qt.RichText)
        label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse | QtCore.Qt.LinksAccessibleByMouse)
        label.setWordWrap(True)
        label.setOpenExternalLinks(True)
        label.setProperty("role", "user")
        label.setProperty("role", "bubble")
        label.setText('<b style="color:#1565c0">Prompt</b>' + markdown_to_html(text))

        box = QtWidgets.QVBoxLayout()
        box.setContentsMargins(0, 0, 0, 0)
        box.setSpacing(2)
        title = QtWidgets.QLabel('<span style="color:#1565c0"><b>You</b></span>')
        title.setTextFormat(QtCore.Qt.RichText)
        box.addWidget(title)
        box.addWidget(label)

        holder = QtWidgets.QWidget()
        holder.setLayout(box)
        item = _ChatItem(role="user", text=text, widget=holder)
        return self._add_item(item)

    def begin_model_message(self) -> _ChatItem:
        box = QtWidgets.QVBoxLayout()
        box.setContentsMargins(0, 0, 0, 0)
        box.setSpacing(4)
        title = QtWidgets.QLabel('<span style="color:#2e7d32"><b>Assistant</b></span>')
        title.setTextFormat(QtCore.Qt.RichText)
        box.addWidget(title)

        holder = QtWidgets.QWidget()
        holder.setLayout(box)
        item = _ChatItem(role="model", widget=holder, body_lay=box, busy=True)
        self._current = item
        return self._add_item(item)

    def _ensure_part(self, pid: int, kind: str) -> dict[str, Any]:
        """Return the state dict for ``pid``, creating its widget if needed.

        New parts are appended to the message layout in arrival order, so text /
        thinking / tool-call blocks interleave exactly as the model produced them.
        """
        cur = self._current
        if cur is None:
            raise RuntimeError("no active model message")
        part = cur.parts.get(pid)
        if part is not None:
            return part
        part = {"kind": kind, "text": "", "tool_name": "", "args": "", "result": "", "widget": None, "label": None}
        cur.parts[pid] = part
        cur.part_order.append(pid)

        if kind == "text":
            label = QtWidgets.QLabel()
            label.setTextFormat(QtCore.Qt.RichText)
            label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
            label.setWordWrap(True)
            label.setProperty("role", "bubble")
            part["label"] = label
            part["widget"] = label
            cur.body_lay.addWidget(label)
        elif kind == "thinking":
            block = _CollapsibleBlock("Thinking", collapsed=True, accent="#8a6d1a", parent=cur.widget)
            label = QtWidgets.QLabel()
            label.setTextFormat(QtCore.Qt.RichText)
            label.setWordWrap(True)
            label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
            label.setProperty("role", "code")
            block.body().addWidget(label)
            part["label"] = label
            part["widget"] = block
            cur.body_lay.addWidget(block)
        elif kind == "tool-call":
            block = _CollapsibleBlock("Tool call", collapsed=True, accent="#00796b", parent=cur.widget)
            label = QtWidgets.QLabel()
            label.setTextFormat(QtCore.Qt.RichText)
            label.setWordWrap(True)
            label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
            label.setProperty("role", "code")
            block.body().addWidget(label)
            part["label"] = label
            part["widget"] = block
            cur.body_lay.addWidget(block)
        return part

    def _on_part_start(self, pid: int, kind: str) -> None:
        if not self._current:
            return
        self._ensure_part(pid, kind)
        self._scroll_to_bottom()

    def _on_turn_start(self) -> None:
        self._current = self.begin_model_message()
        self._set_send_state(True)

    def _on_turn_end(self) -> None:
        if self._current:
            self._current.busy = False
            self._finalize_current()
        self._set_send_state(False)

    def _finalize_current(self) -> None:
        """Apply final rendered text after streaming completes."""
        cur = self._current
        if not cur:
            return
        for pid in cur.part_order:
            part = cur.parts[pid]
            if part["kind"] == "text" and part["label"] is not None:
                body = part["text"]
                if body:
                    part["label"].setText(markdown_to_html(body))
                else:
                    part["label"].setText('<i style="color:#9e9e9e">(no text output)</i>')
        self._current = None

    def _on_text_delta(self, pid: int, chunk: str) -> None:
        if not self._current:
            return
        try:
            part = self._ensure_part(pid, "text")
        except RuntimeError:
            return
        part["text"] += chunk
        if part["label"] is not None:
            # Re-render the full markdown on every delta so headers, lists and
            # code blocks appear progressively while streaming.
            part["label"].setText(markdown_to_html(part["text"]))

    def _on_thinking_delta(self, pid: int, chunk: str) -> None:
        if not self._current:
            return
        try:
            part = self._ensure_part(pid, "thinking")
        except RuntimeError:
            return
        part["text"] += chunk
        if part["label"] is not None:
            part["label"].setText(_escape_html(part["text"]).replace("\n", "<br>"))

    def _on_tool_start(self, pid: int, tool_name: str, args: str) -> None:
        if not self._current:
            return
        try:
            part = self._ensure_part(pid, "tool-call")
        except RuntimeError:
            return
        if tool_name:
            part["tool_name"] = tool_name
        if args:
            part["args"] = args
        self._update_part_tool(part)

    def _on_tool_delta(self, pid: int, tool_name: str, args: str) -> None:
        if not self._current:
            return
        part = self._current.parts.get(pid)
        if part is None:
            return
        if tool_name:
            part["tool_name"] = tool_name
        part["args"] = (part.get("args") or "") + (args or "")
        self._update_part_tool(part)

    def _on_tool_result(self, pid: int, tool_name: str, result: str) -> None:
        if not self._current:
            return
        part = self._current.parts.get(pid)
        if part is None:
            return
        part["result"] = result
        self._update_part_tool(part)

    def _update_part_tool(self, part: dict[str, Any]) -> None:
        label = part.get("label")
        if label is None:
            return
        name = part.get("tool_name") or "Tool call"
        block = part.get("widget")
        if block is not None and hasattr(block, "_btn"):
            block._btn.setText("Tool: %s" % name)
        args = part.get("args") or ""
        result = part.get("result") or ""
        html = []
        if args:
            html.append("<b>args:</b><br>%s" % _escape_html(args).replace("\n", "<br>"))
        if result:
            html.append("<b>result:</b><br>%s" % _escape_html(result[:4000]).replace("\n", "<br>"))
        label.setText("<br>".join(html))
        self._scroll_to_bottom()

    def _on_error(self, msg: str) -> None:
        self._current = None
        label = QtWidgets.QLabel()
        label.setTextFormat(QtCore.Qt.RichText)
        label.setWordWrap(True)
        label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        label.setProperty("role", "error")
        label.setText('<span style="color:#c62828"><b>Error</b></span><br>%s' % _escape_html(msg).replace("\n", "<br>"))
        holder = QtWidgets.QWidget()
        box = QtWidgets.QVBoxLayout(holder)
        box.setContentsMargins(0, 0, 0, 0)
        box.addWidget(label)
        self._add_item(_ChatItem(role="error", text=msg, widget=holder))
        self._set_send_state(False)

    # -- send / stop -------------------------------------------------------

    def _set_send_state(self, running: bool) -> None:
        self._btn_send.setText("Stop" if running else "Send")
        self._btn_send.setEnabled(True)
        if running:
            self._btn_send.setStyleSheet("QPushButton { background:#c62828; color:#fff; border:1px solid #e57373; }")
        else:
            self._btn_send.setStyleSheet("")

    def _on_send_clicked(self) -> None:
        if self._runner and self._runner.running:
            self._runner.stop()
            return
        text = self._input.toPlainText().strip()
        if not text:
            return
        self._input.clear()
        self.add_user_message(text)
        if self._runner:
            self._runner.submit(text)
        else:
            self._on_error("Agent runner is not available.")

    def _on_new_chat(self) -> None:
        if self._runner and self._runner.running:
            self._runner.stop()
        # remove all message widgets
        for item in list(self._items):
            item.widget.setParent(None)
            item.widget.deleteLater()
        self._items.clear()
        self._current = None
        if self._runner:
            self._runner.reset_conversation()
        self._set_send_state(False)

    def apply_settings(self, settings: Settings) -> None:
        self.settings = settings
        self.store.save(settings)
        if self._runner:
            self._runner.set_settings(settings)

    # -- event handling ----------------------------------------------------

    def eventFilter(self, obj: QtCore.QObject, event: QtCore.QEvent) -> bool:
        if obj is self._input and event.type() == QtCore.QEvent.KeyPress:
            key = event.key()
            mods = event.modifiers()
            if key in (QtCore.Qt.Key_Return, QtCore.Qt.Key_Enter) and not (mods & QtCore.Qt.ShiftModifier):
                self._on_send_clicked()
                return True
        return super().eventFilter(obj, event)

    def focus_input(self) -> None:
        self._input.setFocus()

    def shutdown(self) -> None:
        if self._runner:
            self._runner.shutdown()

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        self.shutdown()
        super().closeEvent(event)


# ---------------------------------------------------------------------------
# Settings dialog
# ---------------------------------------------------------------------------


class SettingsDialog(QtWidgets.QDialog):
    """Modal dialog to edit :class:`Settings`."""

    def __init__(self, settings: Settings, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("IDA Copilot - Settings")
        self.setModal(True)
        self.resize(480, 560)
        self._result: Optional[Settings] = None
        self.setStyleSheet(
            """
            QDialog { background: #fafafa; }
            QLabel { color: #1a1a1a; }
            QLineEdit, QSpinBox, QPlainTextEdit { background: #ffffff; color: #1a1a1a; border: 1px solid #c8c8c8; border-radius: 3px; padding: 3px; selection-background-color: #1565c0; }
            QCheckBox { color: #1a1a1a; }
            QPushButton { background: #f0f0f0; color: #1a1a1a; border: 1px solid #b0b0b0; border-radius: 4px; padding: 4px 10px; }
            QPushButton:hover { background: #e4e4e4; }
            """
        )

        form = QtWidgets.QFormLayout()
        form.setSpacing(8)
        self._endpoint = QtWidgets.QLineEdit(settings.endpoint)
        self._endpoint.setPlaceholderText("https://api.openai.com/v1")
        self._api_key = QtWidgets.QLineEdit(settings.api_key)
        self._api_key.setEchoMode(QtWidgets.QLineEdit.Password)
        self._model = QtWidgets.QLineEdit(settings.model)
        self._max_ctx = QtWidgets.QSpinBox()
        self._max_ctx.setRange(1024, 2_000_000)
        self._max_ctx.setSingleStep(1024)
        self._max_ctx.setValue(max(int(settings.max_context_length), 1024))
        self._max_out = QtWidgets.QSpinBox()
        self._max_out.setRange(1, 1_000_000)
        self._max_out.setValue(max(int(settings.max_output_length), 1))
        # Give the numeric fields enough room to show large token counts.
        self._max_ctx.setMinimumWidth(120)
        self._max_out.setMinimumWidth(120)
        self._thinking = QtWidgets.QCheckBox("Enable thinking / reasoning output")
        self._thinking.setChecked(bool(settings.thinking))
        self._system_prompt = QtWidgets.QPlainTextEdit(settings.system_prompt)
        self._system_prompt.setFixedHeight(120)

        form.addRow("Endpoint", self._endpoint)
        form.addRow("API Key", self._api_key)
        form.addRow("Model", self._model)
        form.addRow("Max Context (tokens)", self._max_ctx)
        form.addRow("Max Output (tokens)", self._max_out)
        form.addRow("", self._thinking)
        form.addRow("System Prompt", self._system_prompt)

        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Save | QtWidgets.QDialogButtonBox.Cancel)
        btns.accepted.connect(self._on_save)
        btns.rejected.connect(self.reject)

        root = QtWidgets.QVBoxLayout(self)
        root.addLayout(form)
        root.addWidget(btns)

    def _on_save(self) -> None:
        self._result = Settings(
            endpoint=self._endpoint.text().strip(),
            api_key=self._api_key.text().strip(),
            model=self._model.text().strip(),
            max_context_length=self._max_ctx.value(),
            max_output_length=self._max_out.value(),
            thinking=self._thinking.isChecked(),
            system_prompt=self._system_prompt.toPlainText(),
        )
        self.accept()

    def result_settings(self) -> Optional[Settings]:
        return self._result
