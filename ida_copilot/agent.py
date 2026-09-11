"""Pydantic AI agent factory and streaming runner.

The agent runs in a dedicated worker thread with its own ``asyncio`` event
loop, so IDA's UI thread is never blocked. Streaming events (text deltas,
thinking deltas, tool calls/results) are pushed to the UI through a callback
interface defined by the UI layer.
"""

from __future__ import annotations

import asyncio
import traceback
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

from pydantic_ai import Agent, CancellationToken
from pydantic_ai.messages import (
    FunctionToolCallEvent,
    FunctionToolResultEvent,
    ModelMessage,
    PartDeltaEvent,
    PartEndEvent,
    PartStartEvent,
    TextPartDelta,
    ThinkingPartDelta,
    ToolCallPartDelta,
)
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

from .config import Settings
from .tools import IDA_TOOLS


@dataclass
class StreamEvents:
    """Callback sink that the worker uses to talk to the UI thread.

    Every content callback carries ``part_id`` — a monotonically increasing
    id assigned to each model output part as it starts. The UI uses it to
    render parts (text / thinking / tool-call) in arrival order, so they can
    interleave naturally instead of being grouped by type.
    """

    on_part_start: Optional[Callable[[int, str], Awaitable[None]]] = None  # (part_id, kind)
    on_text_delta: Optional[Callable[[int, str], Awaitable[None]]] = None  # (part_id, chunk)
    on_thinking_delta: Optional[Callable[[int, str], Awaitable[None]]] = None  # (part_id, chunk)
    on_tool_call_start: Optional[Callable[[int, str, str], Awaitable[None]]] = None  # (part_id, tool_name, args)
    on_tool_call_delta: Optional[Callable[[int, str, str], Awaitable[None]]] = None  # (part_id, tool_name, args)
    on_tool_result: Optional[Callable[[int, str, str], Awaitable[None]]] = None  # (part_id, tool_name, result)
    on_turn_start: Optional[Callable[[], Awaitable[None]]] = None
    on_turn_end: Optional[Callable[[list[ModelMessage]], Awaitable[None]]] = None
    on_error: Optional[Callable[[str], Awaitable[None]]] = None


class AgentError(Exception):
    """Raised when the agent cannot be built or run."""


def build_agent(settings: Settings) -> Agent:
    """Construct a Pydantic AI agent from the current settings.

    Raises :class:`AgentError` if the configuration is incomplete.
    """
    endpoint = (settings.endpoint or "").strip().rstrip("/")
    api_key = (settings.api_key or "").strip()
    model_name = (settings.model or "").strip()

    if not endpoint or not model_name:
        raise AgentError(
            "Endpoint and model are required. Open the Setting dialog and configure them."
        )

    provider = OpenAIProvider(base_url=endpoint, api_key=api_key or None)
    model = OpenAIChatModel(model_name, provider=provider)

    agent = Agent(
        model,
        deps_type=dict,
        system_prompt=settings.system_prompt or "You are an expert reverse-engineering assistant embedded in IDA Pro.",
        tools=IDA_TOOLS,
    )
    return agent


def build_model_settings(settings: Settings) -> dict[str, Any]:
    """Return per-run ``model_settings`` derived from user config."""
    s: dict[str, Any] = {"max_tokens": max(int(settings.max_output_length), 1)}
    if settings.thinking:
        s["thinking"] = True
    return s


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------


class AgentRunner:
    """Runs agent turns on a background thread with a dedicated event loop."""

    def __init__(self, settings: Settings, events: StreamEvents) -> None:
        self.settings = settings
        self.events = events
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._task: Optional[Any] = None
        self._thread: Optional[Any] = None
        self._cancel_token = CancellationToken()
        self._history: list[ModelMessage] = []
        self._agent: Optional[Agent] = None
        self._stop_requested = False
        self._loop_ready: Any = None

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        """Start the worker thread (idempotent) and block until its event loop is ready."""
        if self._thread is not None and self._thread.is_alive():
            return
        import threading

        self._stop_requested = False
        self._loop_ready = threading.Event()
        self._thread = threading.Thread(target=self._thread_main, name="ida-copilot-agent", daemon=True)
        self._thread.start()
        # Wait (briefly) for the event loop to be created so submit() works immediately.
        self._loop_ready.wait(timeout=5)

    def _thread_main(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        if self._loop_ready is not None:
            self._loop_ready.set()
        try:
            self._loop.run_forever()
        finally:
            # cancel any pending task on shutdown
            try:
                self._loop.run_until_complete(self._cancel_pending())
            except Exception:
                pass
            self._loop.close()

    async def _cancel_pending(self) -> None:
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except Exception:
                pass

    def stop(self) -> None:
        """Cancel any in-flight generation and stop the loop."""
        self._stop_requested = True
        if self._loop is not None and self._loop.is_running():
            try:
                self._cancel_token.cancel()
            except Exception:
                pass
            # also hard-cancel the asyncio task so the loop frees up promptly
            try:
                self._loop.call_soon_threadsafe(self._schedule_task_cancel)
            except Exception:
                pass

    def _schedule_task_cancel(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()

    def shutdown(self) -> None:
        """Stop the worker thread for good."""
        self.stop()
        if self._loop is not None:
            try:
                self._loop.call_soon_threadsafe(self._loop.stop)
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=3)

    # -- conversation ------------------------------------------------------

    def reset_conversation(self) -> None:
        """Drop in-memory history (used by 'New Chat')."""
        self._history = []

    def set_settings(self, settings: Settings) -> None:
        self.settings = settings
        self._agent = None  # force rebuild on next run

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    # -- run ---------------------------------------------------------------

    def submit(self, user_text: str) -> None:
        """Queue a new user message for generation."""
        if not self._loop or not self._loop.is_running():
            return
        if self.running:
            return
        self._task = asyncio.run_coroutine_threadsafe(self._run_turn(user_text), self._loop)

    async def _run_turn(self, user_text: str) -> None:
        self._cancel_token = CancellationToken()
        try:
            self._agent = build_agent(self.settings)
        except AgentError as e:
            await self._emit_error(str(e))
            return

        settings = build_model_settings(self.settings)

        if self.events.on_turn_start:
            await self.events.on_turn_start()

        try:
            async with self._agent.run_stream_events(
                user_text,
                message_history=list(self._history),
                deps={"mode": "ida"},
                model_settings=settings,
                cancellation_token=self._cancel_token,
            ) as events:
                # part_state maps per-response part index -> globally unique part id.
                # Part indexes restart from 0 on each new model response (e.g. after
                # a tool-call loop), so we assign our own monotonic ids to preserve
                # the true arrival/rendering order.
                part_state: dict[int, int] = {}
                part_kinds: dict[int, str] = {}
                # tool_call_pids maps a unique tool_call_id -> part id.
                # FunctionToolCallEvent/FunctionToolResultEvent carry no part index,
                # so we correlate them to their tool-call part via the per-call id.
                # Using tool_call_id (not tool_name) keeps parallel invocations of
                # the same tool on distinct parts.
                tool_call_pids: dict[str, int] = {}
                part_seq = 0

                async for event in events:
                    if isinstance(event, PartStartEvent):
                        kind = event.part.part_kind
                        part_seq += 1
                        pid = part_seq
                        part_state[event.index] = pid
                        part_kinds[pid] = kind
                        if self.events.on_part_start:
                            await self.events.on_part_start(pid, kind)
                        if kind == "text":
                            content = getattr(event.part, "content", None) or ""
                            if content and self.events.on_text_delta:
                                await self.events.on_text_delta(pid, content)
                        elif kind == "thinking":
                            content = getattr(event.part, "content", None) or ""
                            if content and self.events.on_thinking_delta:
                                await self.events.on_thinking_delta(pid, content)
                        elif kind == "tool-call":
                            # PartStartEvent already carries the tool name, args
                            # and the unique tool_call_id, and it always arrives
                            # before FunctionToolCallEvent, so use it as the
                            # primary source (avoiding "Tool: ?").
                            tool_name = getattr(event.part, "tool_name", "") or ""
                            call_id = getattr(event.part, "tool_call_id", "") or ""
                            args = getattr(event.part, "args", "") or ""
                            if isinstance(args, (dict, list)):
                                import json

                                args = json.dumps(args)
                            if call_id:
                                tool_call_pids[call_id] = pid
                            if self.events.on_tool_call_start:
                                await self.events.on_tool_call_start(pid, tool_name, str(args))

                    elif isinstance(event, PartDeltaEvent):
                        pid = part_state.get(event.index)
                        delta = event.delta
                        if pid is None:
                            continue
                        if isinstance(delta, TextPartDelta):
                            chunk = delta.content_delta or ""
                            if chunk and self.events.on_text_delta:
                                await self.events.on_text_delta(pid, chunk)
                        elif isinstance(delta, ThinkingPartDelta):
                            chunk = delta.content_delta or ""
                            if chunk and self.events.on_thinking_delta:
                                await self.events.on_thinking_delta(pid, chunk)
                        elif isinstance(delta, ToolCallPartDelta):
                            if self.events.on_tool_call_delta:
                                await self.events.on_tool_call_delta(
                                    pid,
                                    delta.tool_name_delta or "",
                                    (delta.args_delta if isinstance(delta.args_delta, str) else "") or "",
                                )

                    elif isinstance(event, PartEndEvent):
                        # Nothing to do: tool results are correlated by tool name.
                        pass

                    elif isinstance(event, FunctionToolCallEvent):
                        # The tool name/args were already emitted from the
                        # PartStartEvent for this tool-call part; skip the
                        # duplicate (FunctionToolCallEvent carries no part index).
                        pass

                    elif isinstance(event, FunctionToolResultEvent):
                        part = event.part
                        tool_name = getattr(part, "tool_name", "?")
                        call_id = getattr(part, "tool_call_id", "") or ""
                        pid = tool_call_pids.get(call_id)
                        if pid is None:
                            continue
                        # The tool return value lives on the ToolReturnPart;
                        # event.content is typically None.
                        content = getattr(part, "content", None)
                        if content is None:
                            content = event.content
                        if isinstance(content, (list, tuple)):
                            content = "\n".join(str(c) for c in content)
                        elif isinstance(content, dict):
                            import json

                            content = json.dumps(content, ensure_ascii=False)
                        if self.events.on_tool_result:
                            await self.events.on_tool_result(pid, tool_name, str(content))

                self._history = list(events.all_messages())
                if self.events.on_turn_end:
                    await self.events.on_turn_end(self._history)
        except asyncio.CancelledError:
            if self.events.on_turn_end:
                await self.events.on_turn_end([])
            return
        except Exception as e:
            await self._emit_error(f"{type(e).__name__}: {e}\n{traceback.format_exc(limit=4)}")

    async def _emit_error(self, msg: str) -> None:
        if self.events.on_error:
            await self.events.on_error(msg)
