"""LLM provider wrapper for PrivPass AI features.

* Uses Anthropic's Claude when ANTHROPIC_API_KEY is set (model: PRIVPASS_AI_MODEL, default claude-sonnet-5).
* Otherwise every feature runs in *offline mode*: deterministic, template/rule-based output built from
  the same data - the demo never depends on network access or a key.
* EVERY outbound payload passes app.redaction.assert_clean first. If anything credential-shaped is
  still present, the call is refused and the feature falls back to offline mode.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Callable

from ..redaction import LeakBlocked, assert_clean

DEFAULT_MODEL = "claude-sonnet-5"
_LOG: list[dict] = []          # last outbound payloads (for the "What the AI saw" panel / tests)


def model_name() -> str:
    return os.environ.get("PRIVPASS_AI_MODEL", DEFAULT_MODEL)


def enabled() -> bool:
    if os.environ.get("PRIVPASS_AI_OFFLINE") == "1":
        return False
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return False
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return True


def status() -> dict:
    return {"provider": "anthropic" if enabled() else "offline", "model": model_name() if enabled() else "rules+templates",
            "redaction_guard": True}


def last_payloads() -> list[dict]:
    return list(_LOG[-10:])


def _client():
    import anthropic
    return anthropic.Anthropic(timeout=45.0, max_retries=1)


def _guard(system: str, messages: list[dict]) -> None:
    blob = system + "\n" + json.dumps(messages, ensure_ascii=False, default=str)
    assert_clean(blob)
    _LOG.append({"system": system[:4000], "messages": messages})
    del _LOG[:-20]


def complete(system: str, prompt: str, max_tokens: int = 1500) -> str:
    """Single-turn completion. Raises on provider errors or redaction failures."""
    messages = [{"role": "user", "content": prompt}]
    _guard(system, messages)
    resp = _client().messages.create(model=model_name(), max_tokens=max_tokens, system=system, messages=messages)
    return "".join(block.text for block in resp.content if getattr(block, "type", "") == "text").strip()


def complete_json(system: str, prompt: str, max_tokens: int = 1800) -> dict:
    text = complete(system + "\nRespond with a single JSON object only - no prose, no code fences.", prompt, max_tokens)
    text = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()
    start, end = text.find("{"), text.rfind("}")
    return json.loads(text[start:end + 1])


def run_tools(system: str, question: str, tools: list[dict], handlers: dict[str, Callable[..., Any]], max_steps: int = 5) -> tuple[str, list[dict]]:
    """Claude tool-use loop over read-only, permission-scoped tools. Tool results are guarded too."""
    messages: list[dict] = [{"role": "user", "content": question}]
    calls: list[dict] = []
    client = _client()
    for _ in range(max_steps):
        _guard(system, messages)
        resp = client.messages.create(model=model_name(), max_tokens=1500, system=system, tools=tools, messages=messages)
        uses = [b for b in resp.content if getattr(b, "type", "") == "tool_use"]
        if not uses:
            return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text").strip(), calls
        messages.append({"role": "assistant", "content": [b.model_dump() for b in resp.content]})
        results = []
        for use in uses:
            fn = handlers.get(use.name)
            try:
                data = fn(**(use.input or {})) if fn else {"error": "unknown tool"}
            except Exception as exc:  # tool errors are reported back to the model
                data = {"error": str(exc)}
            calls.append({"tool": use.name, "args": use.input})
            results.append({"type": "tool_result", "tool_use_id": use.id, "content": json.dumps(data, default=str, ensure_ascii=False)[:12000]})
        messages.append({"role": "user", "content": results})
    return "I gathered the data but hit the tool-step limit; see the tool results above.", calls


def try_ai(fn: Callable[[], Any], fallback: Callable[[], Any]) -> tuple[Any, str]:
    """Run an AI call when enabled; fall back to offline output on any failure (never leak, never crash)."""
    if not enabled():
        return fallback(), "offline"
    try:
        return fn(), f"claude:{model_name()}"
    except LeakBlocked as exc:
        return fallback(), f"offline (redaction guard blocked the request: {exc})"
    except Exception as exc:
        return fallback(), f"offline (AI provider error: {type(exc).__name__})"
