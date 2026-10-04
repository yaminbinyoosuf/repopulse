"""Real tools for RepoPulse Sentinel.

Every function here performs a live call against a public API. Nothing is
mocked, stubbed or replayed. Each tool is wrapped with ``@observe`` from
``cogext-observe`` so the observer sees the true HTTP status of every call.

Rate-limit protection lives in ``guarded()``: a 1.5s pace between requests, a
per-tool circuit breaker after repeated 403s, and a hard stop for the cycle.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import re
import time
from typing import Any, Optional

import config  # noqa: F401  -- sets COGEXT_API_BASE before cogext_observe loads
import httpx
from cogext_observe import observe

log = logging.getLogger("repopulse.tools")

USER_AGENT = "repopulse-sentinel/1.0 (+https://github.com/yaminbinyoosuf/repopulse)"


# --------------------------------------------------------------------------
# shared helpers
# --------------------------------------------------------------------------
def _safe_json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except Exception:
        # Not JSON (gateway HTML, empty body, truncated response...)
        return {"_raw_text": response.text[:500]}


def _github_headers() -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


# --------------------------------------------------------------------------
# the five real tools
# --------------------------------------------------------------------------
@observe
def github_search_repos(query: str, sort: str = "updated", per_page: int = config.MAX_CANDIDATES):
    """GET https://api.github.com/search/repositories

    `sort` is a documented query parameter, not a search qualifier; passing
    "sort:updated" inside `q` makes GitHub reject the query. It is kept as its
    own parameter here so the request is well formed.

    `per_page` controls how many *candidates* are considered, not how many
    repositories are audited.
    """
    r = httpx.get(
        "https://api.github.com/search/repositories",
        params={"q": query, "sort": sort, "order": "desc", "per_page": per_page},
        headers=_github_headers(),
        timeout=config.HTTP_TIMEOUT,
    )
    return {"status_code": r.status_code, "body": _safe_json(r)}


@observe
def github_get_file(repo_full_name: str, path: str):
    """GET https://api.github.com/repos/{owner}/{repo}/contents/{path}"""
    r = httpx.get(
        f"https://api.github.com/repos/{repo_full_name}/contents/{path}",
        headers=_github_headers(),
        timeout=config.HTTP_TIMEOUT,
    )
    return {"status_code": r.status_code, "body": _safe_json(r)}


@observe
def pypi_get_metadata(package: str):
    """GET https://pypi.org/pypi/{package}/json"""
    r = httpx.get(f"https://pypi.org/pypi/{package}/json", timeout=config.HTTP_TIMEOUT)
    return {"status_code": r.status_code, "body": _safe_json(r)}


@observe
def npm_get_metadata(package: str):
    """GET https://registry.npmjs.org/{package}"""
    r = httpx.get(f"https://registry.npmjs.org/{package}", timeout=config.HTTP_TIMEOUT)
    return {"status_code": r.status_code, "body": _safe_json(r)}


@observe
def osv_query(package: str, version: Optional[str], ecosystem: str = "PyPI"):
    """POST https://api.osv.dev/v1/query

    ``version`` is omitted entirely when a manifest does not pin an exact
    version. Sending a placeholder like "0.0.0" would query a version that does
    not exist and silently report "no vulnerabilities", which is a false
    negative rather than a real answer. Without a version, OSV returns every
    advisory that affects the package, which is a real answer.
    """
    payload: dict = {"package": {"name": package, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version
    r = httpx.post("https://api.osv.dev/v1/query", json=payload, timeout=config.HTTP_TIMEOUT)
    return {"status_code": r.status_code, "body": _safe_json(r)}


# --------------------------------------------------------------------------
# rate-limit protection
# --------------------------------------------------------------------------
class RateLimitHit(RuntimeError):
    """A tool returned HTTP 403 (rate limit or secondary rate limit)."""


class CircuitOpen(RuntimeError):
    """The tool was disabled for the remainder of this cycle."""


_consecutive_403: dict[str, int] = {}
_consecutive_transport_error: dict[str, int] = {}
_disabled_tools: set[str] = set()

# A complete tally of every call this cycle made. cogext-observe only retains
# the 20 most recent calls, which is not enough to report a full cycle.
_calls: list[dict] = []


def reset_guards() -> None:
    """Call at the start of every cycle."""
    _consecutive_403.clear()
    _consecutive_transport_error.clear()
    _disabled_tools.clear()
    _calls.clear()


def call_log() -> list[dict]:
    return list(_calls)


def call_tally() -> dict[str, int]:
    tally: dict[str, int] = {}
    for call in _calls:
        key = str(call["status"])
        tally[key] = tally.get(key, 0) + 1
    return dict(sorted(tally.items()))


def failures() -> list[dict]:
    return [
        c
        for c in _calls
        if (isinstance(c["status"], int) and c["status"] >= 400)
        or c["status"] == "transport_error"
    ]


def disabled_tools() -> list[str]:
    return sorted(_disabled_tools)


def guarded(tool_name: str, fn, *args, **kwargs):
    """Pace, detect 403s, and trip a per-tool circuit breaker.

    A 403 is still recorded by @observe before this returns, so the observer
    sees the real failure. This only decides whether the cycle keeps calling.
    """
    if tool_name in _disabled_tools:
        raise CircuitOpen(f"{tool_name} disabled for this cycle after repeated failures")

    try:
        result = fn(*args, **kwargs)
    except Exception as exc:
        # @observe has already recorded this call as a failure (http_status 500,
        # body {"error": ...}) and re-raised. A transport error on one call --
        # timeout, DNS failure, reset connection -- must not kill the cycle, and
        # a network outage must not record forty of them.
        count = _consecutive_transport_error.get(tool_name, 0) + 1
        _consecutive_transport_error[tool_name] = count
        _calls.append(
            {"tool": tool_name, "status": "transport_error", "error": type(exc).__name__}
        )
        log.error(
            "call %s raised %s (%d consecutive): %s",
            tool_name,
            type(exc).__name__,
            count,
            exc,
        )
        if count >= config.CIRCUIT_BREAKER_THRESHOLD:
            _disabled_tools.add(tool_name)
            log.error(
                "circuit breaker OPEN for %s after %d consecutive transport errors",
                tool_name,
                count,
            )
        return {
            "status_code": 0,
            "transport_error": True,
            "body": {"error": f"{type(exc).__name__}: {exc}"},
        }

    _consecutive_transport_error[tool_name] = 0
    status = (result or {}).get("status_code") if isinstance(result, dict) else None
    _calls.append({"tool": tool_name, "status": status})
    log.info("call %s(%s) -> HTTP %s", tool_name, ", ".join(repr(a)[:40] for a in args), status)

    if status == 403:
        count = _consecutive_403.get(tool_name, 0) + 1
        _consecutive_403[tool_name] = count
        log.warning("403 from %s (consecutive: %d)", tool_name, count)
        if count >= config.CIRCUIT_BREAKER_THRESHOLD:
            _disabled_tools.add(tool_name)
            log.error(
                "circuit breaker OPEN for %s after %d consecutive 403s; "
                "tool disabled for the rest of this cycle",
                tool_name,
                count,
            )
        raise RateLimitHit(tool_name)

    _consecutive_403[tool_name] = 0
    time.sleep(config.SLEEP_BETWEEN_REQUESTS)
    return result


# --------------------------------------------------------------------------
# manifest reading
# --------------------------------------------------------------------------
MANIFEST_PATHS = ("requirements.txt", "pyproject.toml")


def decode_manifest(result: dict) -> Optional[str]:
    """Decode the base64 `content` field of a GitHub contents response."""
    body = result.get("body")
    if not isinstance(body, dict):
        return None
    raw = body.get("content")
    if not raw or body.get("encoding") not in (None, "base64"):
        return None
    try:
        return base64.b64decode(raw).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError, TypeError) as exc:
        # e.g. content: "not base64 at all" with a 200 status
        log.warning("base64 decode failed for manifest: %s", exc)
        return None


_REQ_LINE = re.compile(
    r"""^\s*
    (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)
    \s*(?:\[[^\]]*\])?                       # extras
    \s*(?P<op>===|==|~=|!=|>=|<=|>|<)?
    \s*(?P<version>[^\s;,\\]*)?
    """,
    re.VERBOSE,
)

_PIN_OPS = ("==", "===")


def _clean_requirement_line(line: str) -> str:
    line = line.split("#", 1)[0].strip()
    if not line:
        return ""
    if line.startswith(("-", "git+", "http://", "https://", ".", "/")):
        return ""
    # drop environment markers
    return line.split(";", 1)[0].strip()


def parse_requirements_txt(text: str) -> list[dict]:
    deps = []
    for raw_line in text.splitlines():
        line = _clean_requirement_line(raw_line)
        if not line:
            continue
        m = _REQ_LINE.match(line)
        if not m:
            continue
        name = m.group("name")
        op = m.group("op")
        version = m.group("version") or None
        pinned = bool(op in _PIN_OPS and version)
        deps.append(
            {
                "name": name,
                "version": version if pinned else None,
                "pinned": pinned,
                "specifier": f"{op}{version}" if op and version else None,
                "raw": raw_line.strip(),
            }
        )
    return deps


def parse_pyproject_toml(text: str) -> list[dict]:
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
        log.warning("tomllib unavailable; cannot parse pyproject.toml")
        return []

    try:
        data = tomllib.loads(text)
    except Exception as exc:
        log.warning("pyproject.toml did not parse: %s", exc)
        return []

    specs: list[str] = []
    project = data.get("project") or {}
    if isinstance(project.get("dependencies"), list):
        specs.extend(str(s) for s in project["dependencies"])

    poetry = ((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
    if isinstance(poetry, dict):
        for name, constraint in poetry.items():
            if name.lower() == "python":
                continue
            specs.append(f"{name}{constraint}" if isinstance(constraint, str) else str(name))

    return parse_requirements_txt("\n".join(specs))


def parse_dependencies(manifest: dict) -> list[dict]:
    """Parse a fetched manifest result into [{name, version, pinned, ...}]."""
    path = manifest.get("path", "")
    text = decode_manifest(manifest)
    if not text:
        return []
    if path.endswith("pyproject.toml"):
        return parse_pyproject_toml(text)
    return parse_requirements_txt(text)
