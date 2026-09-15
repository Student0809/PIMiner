"""Provider routing for IPI-Arena target models.

Maps a target model id to an OpenAI-compatible (base_url, api_key) so a single
`openai.OpenAI(...)` client can drive OpenAI, DeepSeek, and Gemini targets (and,
for the harness path, Anthropic via its OpenAI-compatible endpoint). The
single-completion path in reward.py still uses the native Anthropic SDK for
`claude-*` (it needs the message/image conversion), so it routes claude
separately via `is_anthropic_target`.

Keys (set whichever targets you use):
  OPENAI_API_KEY                          gpt-*/o-series
  DEEPSEEK_API_KEY                         deepseek-*
  GEMINI_API_KEY or GOOGLE_API_KEY         gemini-*
  ANTHROPIC_API_KEY / PIMINER_TARGET_ANTHROPIC_API_KEY   claude-* (harness path)
"""
from __future__ import annotations

import os

OPENAI_BASE = "https://api.openai.com/v1"
ANTHROPIC_OPENAI_BASE = "https://api.anthropic.com/v1/"      # Anthropic's OpenAI-compat layer
DEEPSEEK_BASE = "https://api.deepseek.com"                   # OpenAI-compatible
DEEPSEEK_ANTHROPIC_BASE = "https://api.deepseek.com/anthropic"  # native Anthropic Messages API
GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/openai/"  # OpenAI-compatible


def is_anthropic_target(model: str) -> bool:
    return model.lower().startswith("claude")


def is_anthropic_native(model: str) -> bool:
    """Targets driven through the native Anthropic Messages API (SDK) rather than
    the OpenAI-compatible chat-completions path. DeepSeek's v4 models route here:
    their OpenAI-compatible endpoint runs in thinking mode and demands a
    `reasoning_content` round-trip the harness doesn't perform, whereas the
    Anthropic-compatible endpoint works cleanly (we call it with thinking disabled).
    """
    m = model.lower()
    return m.startswith("claude") or m.startswith("deepseek")


def anthropic_endpoint(model: str) -> tuple[str | None, str]:
    """Return (base_url, api_key) for the native Anthropic SDK.

    base_url is None for claude (default api.anthropic.com); deepseek routes to
    its Anthropic-compatible endpoint. Raises on a missing key.
    """
    m = model.lower()
    if m.startswith("claude"):
        return None, _require_key("ANTHROPIC_API_KEY", "PIMINER_TARGET_ANTHROPIC_API_KEY")
    if m.startswith("deepseek"):
        return DEEPSEEK_ANTHROPIC_BASE, _require_key("DEEPSEEK_API_KEY")
    raise ValueError(f"{model!r} is not an Anthropic-native target")


def is_openai_reasoning(model: str) -> bool:
    """gpt-5 / o-series: need max_completion_tokens and reject temperature."""
    return model.lower().startswith(("gpt-5", "o1", "o3", "o4"))


def _require_key(*names: str) -> str:
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    raise RuntimeError(f"missing API key for target: set one of {', '.join(names)}")


def openai_compatible_endpoint(model: str) -> tuple[str, str]:
    """Return (base_url, api_key) for an OpenAI-compatible client for `model`.

    Covers OpenAI, DeepSeek, Gemini, and Anthropic (via its OpenAI-compat layer,
    used by the harness path). Raises on an unsupported model or a missing key.
    """
    m = model.lower()
    if m.startswith(("gpt-", "o1", "o3", "o4", "chatgpt")):
        return OPENAI_BASE, _require_key("OPENAI_API_KEY")
    if m.startswith("deepseek"):
        return DEEPSEEK_BASE, _require_key("DEEPSEEK_API_KEY")
    if m.startswith("gemini"):
        return GEMINI_BASE, _require_key("GEMINI_API_KEY", "GOOGLE_API_KEY")
    if m.startswith("claude"):
        return ANTHROPIC_OPENAI_BASE, _require_key("ANTHROPIC_API_KEY", "PIMINER_TARGET_ANTHROPIC_API_KEY")
    raise ValueError(
        f"Unsupported target_model {model!r} for IPI-Arena. "
        "Supported: gpt-*/o-series, claude-*, deepseek-*, gemini-*."
    )
