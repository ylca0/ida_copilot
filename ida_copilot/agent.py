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
    """Callback sink that the worker uses to talk to the UI thread."""

    on_text_delta: Optional[Callable[[str], Awaitable[None]]] = None
    on_thinking_delta: Optional[Callable[[str], Awaitable[None]]] = None
    on_tool_call_start: Optional[Callable[[str, str], Awaitable[None]]] = None  # (tool_name, args_so_far)
    on_tool_call_delta: Optional[Callable[[str, str], Awaitable[None]]] = None
    on_tool_result: Optional[Callable[[str, str], Awaitable[None]]] = None  # (tool_name, result)
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
                part_state: dict[int, dict[str, Any]] = {}

                async for event in events:
                    if isinstance(event, PartStartEvent):
                        kind = event.part.part_kind
                        state = {"kind": kind, "text": "", "tool_name": "", "args": ""}
                        part_state[event.index] = state
                        if kind == "text":
                            content = getattr(event.part, "content", None) or ""
                            if content:
                                state["text"] += content
                                if self.events.on_text_delta:
                                    await self.events.on_text_delta(content)
                        elif kind == "thinking":
                            content = getattr(event.part, "content", None) or ""
                            if content:
                                state["text"] += content
                                if self.events.on_thinking_delta:
                                    await self.events.on_thinking_delta(content)

                    elif isinstance(event, PartDeltaEvent):
                        state = part_state.get(event.index, {"kind": "", "text": "", "tool_name": "", "args": ""})
                        delta = event.delta
                        if isinstance(delta, TextPartDelta):
                            chunk = delta.content_delta or ""
                            state["text"] += chunk
                            if self.events.on_text_delta:
                                await self.events.on_text_delta(chunk)
                        elif isinstance(delta, ThinkingPartDelta):
                            chunk = delta.content_delta or ""
                            state["text"] += chunk
                            if self.events.on_thinking_delta:
                                await self.events.on_thinking_delta(chunk)
                        elif isinstance(delta, ToolCallPartDelta):
                            state["args"] += (delta.args_delta if isinstance(delta.args_delta, str) else "") or ""
                            if delta.tool_name_delta:
                                state["tool_name"] += delta.tool_name_delta
                            if self.events.on_tool_call_delta:
                                await self.events.on_tool_call_delta(state["tool_name"], state["args"])

                    elif isinstance(event, FunctionToolCallEvent):
                        part = event.part
                        args = part.args or ""
                        if isinstance(args, (dict, list)):
                            import json

                            args = json.dumps(args)
                        if self.events.on_tool_call_start:
                            await self.events.on_tool_call_start(part.tool_name, str(args))

                    elif isinstance(event, FunctionToolResultEvent):
                        part = event.part
                        tool_name = getattr(part, "tool_name", "?")
                        content = event.content
                        if isinstance(content, (list, tuple)):
                            content = "\n".join(str(c) for c in content)
                        if self.events.on_tool_result:
                            await self.events.on_tool_result(tool_name, str(content))

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
