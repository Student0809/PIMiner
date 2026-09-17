#!/usr/bin/env python3
"""Turn Claude Code stream-json into concise, line-buffered progress messages.

The original JSONL is retained by the shell driver's ``tee``.  This formatter
only controls what is forwarded to the driver's human-facing log.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import json
import re
import sys
from typing import Any


def compact(value: Any, limit: int = 360) -> str:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def emit(prefix: str, context: str, message: str) -> None:
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    print(f"{prefix} {timestamp} {context} | {message}", flush=True)


def content_blocks(message: Any) -> list[dict[str, Any]]:
    if not isinstance(message, dict):
        return []
    content = message.get("content") or []
    return [block for block in content if isinstance(block, dict)]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--context", required=True)
    args = parser.parse_args()
    prefix = args.prefix
    context = args.context

    for raw_line in sys.stdin:
        line = raw_line.rstrip("\r\n")
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            emit(prefix, context, f"runtime: {compact(line)}")
            continue
        if not isinstance(event, dict):
            emit(prefix, context, f"runtime event: {compact(event)}")
            continue

        event_type = event.get("type")
        if event_type == "system":
            subtype = event.get("subtype", "event")
            # Emitted for every reasoning-token update by some providers. Keep
            # it in the raw JSONL written by tee, but suppress it from the
            # human-facing driver log to avoid high-frequency noise.
            if subtype == "thinking_tokens":
                continue
            model = event.get("model") or (event.get("message") or {}).get("model")
            suffix = f" model={model}" if model else ""
            emit(prefix, context, f"system/{subtype}{suffix}")
        elif event_type == "assistant":
            blocks = content_blocks(event.get("message"))
            for block in blocks:
                kind = block.get("type")
                if kind == "tool_use":
                    tool = block.get("name", "unknown")
                    tool_input = block.get("input") or {}
                    detail = (tool_input.get("command") or tool_input.get("file_path")
                              or tool_input.get("path") or tool_input)
                    emit(prefix, context, f"tool call: {tool} — {compact(detail)}")
                elif kind == "text" and compact(block.get("text")):
                    emit(prefix, context, f"assistant: {compact(block.get('text'))}")
                elif kind == "thinking":
                    # Expose activity, not private chain-of-thought content.
                    emit(prefix, context, f"reasoning block complete ({len(str(block.get('thinking') or ''))} chars)")
        elif event_type == "user":
            for block in content_blocks(event.get("message")):
                if block.get("type") == "tool_result":
                    status = "error" if block.get("is_error") else "ok"
                    emit(prefix, context, f"tool result ({status}): {compact(block.get('content'))}")
        elif event_type == "result":
            subtype = event.get("subtype", "complete")
            duration = event.get("duration_ms")
            duration_text = f" duration={duration / 1000:.1f}s" if isinstance(duration, (int, float)) else ""
            result = compact(event.get("result"))
            emit(prefix, context, f"result/{subtype}{duration_text}" + (f": {result}" if result else ""))
        elif event_type == "rate_limit_event":
            emit(prefix, context, f"rate limit: {compact(event)}")
        elif event_type == "stream_event":
            inner = event.get("event") or {}
            if inner.get("type") == "message_start":
                model = (inner.get("message") or {}).get("model")
                emit(prefix, context, "generation started" + (f" model={model}" if model else ""))
            elif inner.get("type") == "content_block_start":
                kind = (inner.get("content_block") or {}).get("type", "content")
                emit(prefix, context, f"streaming {kind}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
