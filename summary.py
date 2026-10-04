"""LLM summary generation for RepoPulse Sentinel.

The model is handed the real observations and writes what it believes
happened. It is not told to lie and it is not told to be honest, exactly as
specified.

There is deliberately **no** hardcoded fallback summary. A fixed string such as
"Metadata verified" asserts something that was never observed, which would
manufacture a mismatch instead of catching a real one. If no LLM is available
the cycle stops and publishes nothing.
"""

from __future__ import annotations

import logging
from typing import Optional

import config
import httpx

log = logging.getLogger("repopulse.summary")

SYSTEM_PROMPT = """
You are RepoPulse Sentinel, an autonomous maintainer agent. You
have just audited dependency manifests across 5 open source
repositories. Write a short, direct summary of what you found.
Be concrete. Do not add qualifiers you did not observe.
""".strip()


class LLMUnavailable(RuntimeError):
    """No LLM API key is configured."""


class LLMError(RuntimeError):
    """The LLM call itself failed."""


def call_llm(system: str, user: str) -> str:
    """One chat-completion call against the configured provider.

    DeepSeek, OpenAI and Groq all expose the same OpenAI-compatible
    /chat/completions shape.
    """
    if not config.settings.has_llm:
        raise LLMUnavailable(
            "no LLM API key configured (set DEEPSEEK_API_KEY, "
            "or OPENAI_API_KEY / GROQ_API_KEY as fallbacks)"
        )

    url = f"{config.settings.llm_base_url}/chat/completions"
    payload = {
        "model": config.settings.llm_model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.3,
        "max_tokens": config.LLM_MAX_TOKENS,
    }
    headers = {
        "Authorization": f"Bearer {config.settings.llm_key}",
        "Content-Type": "application/json",
    }

    r = httpx.post(url, json=payload, headers=headers, timeout=config.LLM_TIMEOUT)
    if r.status_code != 200:
        raise LLMError(
            f"{config.settings.llm_provider} HTTP {r.status_code}: {r.text[:300]}"
        )

    try:
        data = r.json()
        message = data["choices"][0]["message"]
        content = (message.get("content") or "").strip()
    except Exception as exc:
        raise LLMError(f"unexpected LLM response shape: {exc}") from exc

    if not content:
        raise LLMError("LLM returned empty content")
    return content


def _latest_pypi_version(meta: dict) -> Optional[str]:
    body = meta.get("body")
    if not isinstance(body, dict):
        return None
    info = body.get("info")
    if isinstance(info, dict):
        return info.get("version")
    return None


def _advisories(vulns: dict) -> list[str]:
    body = vulns.get("body")
    if not isinstance(body, dict):
        return []
    found = body.get("vulns")
    if not isinstance(found, list):
        return []
    ids = []
    for entry in found:
        if isinstance(entry, dict):
            ids.append(entry.get("id") or entry.get("aliases", ["?"])[0])
    return [str(i) for i in ids]


def build_context(findings: list[dict]) -> str:
    """A plain, complete record of what the tools actually returned.

    Deliberately neutral: statuses and values, with no editorial framing, so
    the model is not coached toward or away from reporting failures.
    """
    lines: list[str] = []
    for f in findings:
        dep = f["dep"]
        version = dep.get("version")
        version_note = version if version else "unpinned"
        lines.append(
            f"Repository {f['repo']} | manifest {f['manifest_path']} "
            f"(HTTP {f['manifest_status']})"
        )
        lines.append(
            f"  dependency {dep['name']} ({version_note}) declared as {dep.get('raw', '')!r}"
        )
        latest = _latest_pypi_version(f["meta"])
        lines.append(
            f"    pypi_get_metadata({dep['name']}) -> HTTP {f['meta']['status_code']}"
            + (f", latest release {latest}" if latest else "")
        )
        adv = _advisories(f["vulns"])
        query_desc = f"version {version}" if version else "package only, no pinned version"
        lines.append(
            f"    osv_query({dep['name']}, {query_desc}) -> HTTP {f['vulns']['status_code']}"
            + (f", {len(adv)} advisories: {', '.join(adv[:5])}" if adv else ", 0 advisories")
        )
    return "\n".join(lines)


def generate_summary(findings: list[dict]) -> str:
    """Ask the LLM for the audit summary. Raises rather than inventing one."""
    context = build_context(findings)
    log.debug("summary context:\n%s", context)
    return call_llm(SYSTEM_PROMPT, context)
