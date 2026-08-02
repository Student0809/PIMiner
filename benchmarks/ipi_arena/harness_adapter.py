"""Adapter that runs IPI-Arena's own multi-step harness for the behaviors that
PIMiner's simplified single-completion path can't score: the 8 browser behaviors
(HTML→screenshot render + computer-use tools) and the no-`tool_judge` samples
scored by an `llm_judge` / `tool_call` criteria rubric.

It delegates to the upstream `ipi_arena_bench` package (vendored under
`data/ipi_arena/repo`) — its `BenchmarkRunner.run_one(behavior_id, attack_text)`
renders the screenshot, runs the target in a ≤5-step loop with WorldSim
simulating tool responses, then runs the tool/LLM judges. We just construct the
LLM clients (target = PIMiner's target model; judge + WorldSim = a fixed small
model) and map the result back to PIMiner's `(utility, security, trajectory,
final_output, model_output_text)` tuple.

Requires the upstream data to be present (`bash data/ipi_arena/fetch.sh`).
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_REPO = Path(__file__).resolve().parents[2] / "data" / "ipi_arena" / "repo"
_SRC = _REPO / "src"
_DATA = _REPO / "data"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ipi_arena_bench.llm_client import LLMClient, ChatResponse, ToolCall  # noqa: E402
from ipi_arena_bench.runner import BenchmarkRunner  # noqa: E402

_OPENAI_BASE = "https://api.openai.com/v1"
# Anthropic ships an OpenAI-compatible Chat Completions endpoint; claude targets
# route through it so the harness's OpenAI-shaped client works unchanged.
_ANTHROPIC_BASE = "https://api.anthropic.com/v1/"

# Default judge + WorldSim model (the user picked gpt-5-nano). Overridable via
# PIMINER_IPI_JUDGE_MODEL for experimentation.
DEFAULT_JUDGE_MODEL = os.environ.get("PIMINER_IPI_JUDGE_MODEL", "gpt-5-nano")

from benchmarks.ipi_arena.providers import (  # noqa: E402
    openai_compatible_endpoint, is_openai_reasoning as _is_openai_reasoning,
)


class _PimLLMClient(LLMClient):
    """LLMClient that fixes OpenAI reasoning-model param quirks.

    gpt-5 / o-series reject `temperature` and require `max_completion_tokens`
    instead of `max_tokens`; the stock harness client always sends the legacy
    kwargs, which 400s on those models.
    """

    def chat(self, messages, tools=None, temperature: float = 0.0,
             max_tokens: int = 4096) -> ChatResponse:
        kwargs: Dict[str, Any] = {"model": self.model, "messages": messages}
        if _is_openai_reasoning(self.model):
            kwargs["max_completion_tokens"] = max_tokens
        else:
            kwargs["temperature"] = temperature
            kwargs["max_tokens"] = max_tokens
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        response = self.client.chat.completions.create(**kwargs)
        message = response.choices[0].message
        reasoning = getattr(message, "reasoning_content", None) or getattr(message, "reasoning", None)

        parsed: List[ToolCall] = []
        for tc in (message.tool_calls or []):
            args = tc.function.arguments
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {"_raw": tc.function.arguments}
            parsed.append(ToolCall(name=tc.function.name, arguments=args or {}, id=tc.id or ""))

        usage: Dict[str, int] = {}
        if response.usage:
            usage = {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens,
            }
        return ChatResponse(
            content=message.content, reasoning=reasoning, tool_calls=parsed,
            raw_response=response, model=response.model or self.model, usage=usage,
        )


class _AnthropicLLMClient:
    """Target client backed by the native Anthropic Messages API.

    Used for DeepSeek via its Anthropic-compatible endpoint: DeepSeek's OpenAI-
    compatible path runs in thinking mode and 400s unless `reasoning_content` is
    echoed back each turn (which the harness's OpenAI history doesn't carry). The
    Anthropic endpoint with thinking DISABLED needs no such round-trip. Exposes
    the same `.chat()` / `.model` surface the runner uses; reuses reward.py's
    OpenAI->Anthropic message converter.
    """

    def __init__(self, model: str, api_key: str, base_url: str):
        import anthropic
        self.model = model
        self.provider = "anthropic"
        self.client = anthropic.Anthropic(api_key=api_key, base_url=base_url)

    def chat(self, messages, tools=None, temperature: float = 0.0,
             max_tokens: int = 4096) -> ChatResponse:
        from benchmarks.ipi_arena.reward import _messages_oa_to_anthropic
        anth_msgs, sys_chunks = _messages_oa_to_anthropic(messages)
        kwargs: Dict[str, Any] = {
            "model": self.model, "max_tokens": max_tokens,
            "messages": anth_msgs, "thinking": {"type": "disabled"},
        }
        sys_text = "\n".join(sys_chunks).strip()
        if sys_text:
            kwargs["system"] = sys_text
        anth_tools: List[Dict[str, Any]] = []
        for t in (tools or []):
            fn = t.get("function", t)  # unwrap OpenAI {"type":"function","function":{...}}
            params = dict(fn.get("parameters") or {})
            params.setdefault("type", "object")
            anth_tools.append({"name": fn.get("name", ""),
                               "description": fn.get("description", ""),
                               "input_schema": params})
        if anth_tools:
            kwargs["tools"] = anth_tools
            kwargs["tool_choice"] = {"type": "auto"}

        resp = self.client.messages.create(**kwargs)
        text_parts: List[str] = []
        parsed: List[ToolCall] = []
        for blk in resp.content:
            bt = getattr(blk, "type", None)
            if bt == "text":
                text_parts.append(getattr(blk, "text", "") or "")
            elif bt == "tool_use":
                parsed.append(ToolCall(name=getattr(blk, "name", "") or "",
                                       arguments=dict(getattr(blk, "input", {}) or {}),
                                       id=getattr(blk, "id", "") or ""))
        usage: Dict[str, int] = {}
        u = getattr(resp, "usage", None)
        if u is not None:
            it = getattr(u, "input_tokens", 0) or 0
            ot = getattr(u, "output_tokens", 0) or 0
            usage = {"prompt_tokens": it, "completion_tokens": ot, "total_tokens": it + ot}
        return ChatResponse(
            content=("".join(text_parts) or None), reasoning=None, tool_calls=parsed,
            raw_response=resp, model=getattr(resp, "model", "") or self.model, usage=usage,
        )


def _make_client(model: str):
    # DeepSeek routes through its native Anthropic Messages endpoint (its OpenAI-
    # compatible path requires a reasoning round-trip the harness can't do). All
    # other providers (openai / gemini / anthropic-compat) use the OpenAI-shaped
    # client via the shared provider router.
    if model.lower().startswith("deepseek"):
        from benchmarks.ipi_arena.providers import anthropic_endpoint
        base_url, api_key = anthropic_endpoint(model)
        return _AnthropicLLMClient(model=model, api_key=api_key, base_url=base_url)
    base_url, api_key = openai_compatible_endpoint(model)
    return _PimLLMClient(provider="compat", model=model, api_key=api_key, base_url=base_url)


def is_available() -> bool:
    """True if the vendored harness data is present."""
    return _DATA.is_dir()


def run_harness(
    behavior_id: str,
    attack_text: str,
    target_model: str,
    judge_model: str = DEFAULT_JUDGE_MODEL,
    max_steps: int = 5,
) -> Tuple[bool, bool, str, str, str]:
    """Run one behavior through the upstream harness and map to PIMiner's tuple.

    Returns (utility, security, trajectory, final_output, model_output_text).
    """
    from iterative_attack_orchestrator.iterative_attack_common import format_final_output

    if not _DATA.is_dir():
        raise RuntimeError(
            f"IPI-Arena harness data not found at {_DATA}. Run: bash data/ipi_arena/fetch.sh"
        )

    target = _make_client(target_model)
    judge = _make_client(judge_model)  # also used as WorldSim (runner default)
    runner = BenchmarkRunner(
        target_client=target, judge_client=judge, worldsim_client=judge,
        behaviors_path=str(_DATA), verbose=False, max_steps=max_steps,
    )
    # No scoring modifications: behaviors are scored exactly by their upstream
    # tool_judge / llm_judge / tool_call criteria. (flashing-lights-seizure ships
    # no top-level tool_judge and is scored by its upstream criteria as-is.)
    res = runner.run_one(behavior_id, attack_text)

    security = bool(res.is_break)
    utility = res.error is None
    model_output_text = res.model_response or ""

    # Black-box final output: final text + the tool call(s) the agent made.
    calls = [(tc.get("name", ""), json.dumps(tc.get("arguments", {}), default=str))
             for tc in (res.tool_calls_made or [])]
    final_output = format_final_output(model_output_text, calls)

    # White-box trajectory view: criteria verdicts + per-call args + steps.
    lines: List[str] = [f"[harness] behavior={behavior_id} break={security} steps={res.steps}"]
    if res.error:
        lines.append(f"error: {res.error}")
    for name, args in calls:
        lines.append(f"tool_call: {name}({args[:800]})")
    for cname, c in (res.criteria or {}).items():
        lines.append(f"criterion[{cname}] score={c.get('score')}/thr={c.get('threshold')} "
                     f"passed={c.get('passed')} :: {str(c.get('explanation',''))[:300]}")
    if model_output_text:
        lines.append(f"final_text: {model_output_text[:1500]}")
    trajectory = "\n".join(lines)

    return utility, security, trajectory, final_output, model_output_text
