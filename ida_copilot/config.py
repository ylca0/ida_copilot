"""Configuration model and JSON persistence for IDA Copilot.

Settings are stored as JSON in IDA's user config directory so they survive
restarts. The API key is stored locally (never logged) in plaintext; users who
want stronger protection can use environment variables / their OS keychain.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

CONFIG_FILE_NAME = "ida_copilot.json"


def get_user_config_dir() -> Path:
    """Return the directory used to store IDA Copilot settings."""
    if os.name == "nt":
        base = os.getenv("APPDATA") or str(Path.home())
        d = Path(base) / "Hex-Rays" / "IDA Pro"
    elif os.name == "posix":
        home = Path.home()
        d = home / ".idapro"
    else:  # pragma: no cover - only win/posix are realistically used
        d = Path.home() / ".idapro"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _env_default(key: str, default: str) -> str:
    return os.environ.get(key, default)


@dataclass
class Settings:
    """All user-configurable options for the plugin."""

    endpoint: str = field(default_factory=lambda: _env_default("OPENAI_BASE_URL", "https://api.openai.com/v1"))
    api_key: str = field(default_factory=lambda: _env_default("OPENAI_API_KEY", ""))
    model: str = field(default_factory=lambda: _env_default("OPENAI_MODEL", "gpt-4o-mini"))
    max_context_length: int = 32000
    max_output_length: int = 4096
    request_timeout: int = 60  # seconds, for model API requests
    tool_timeout: int = 15  # seconds, for tool execution
    thinking: bool = True
    system_prompt: str = "You are an expert reverse-engineering assistant embedded in IDA Pro. You can inspect the database and modify it with the provided tools. Prefer concise, actionable answers. Quote addresses as hex. When the user asks for a change, perform it with a tool call and confirm what you changed."

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Settings":
        known = {f for f in Settings.__dataclass_fields__}
        filtered = {k: v for k, v in d.items() if k in known}
        return Settings(**filtered)


class ConfigStore:
    """Loads and saves :class:`Settings` to disk."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (get_user_config_dir() / CONFIG_FILE_NAME)

    def load(self) -> Settings:
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return Settings.from_dict(data)
            except (OSError, ValueError, TypeError):
                # Corrupt config: fall back to defaults rather than crash.
                pass
        return Settings()

    def save(self, settings: Settings) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(settings.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.path)

    def delete(self) -> None:
        try:
            self.path.unlink()
        except OSError:
            pass
