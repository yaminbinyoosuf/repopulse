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
# payload bounding
#
# Whatever a tool returns is copied into the observed event and stored in
# live_sessions. Storing whole API bodies is what produced a 14.8 MB session
# and a 57014 statement timeout on publish, so every body is bounded here.
#
# Three stages, tightest last:
#   1. _truncate_dict -- caps every individual string field
#   2. _slim_*        -- a per-tool projection keeping only what the agent
#                        actually reads (repo names, the latest version,
#                        advisory ids), dropping bulk such as PyPI's `releases`
#                        map or npm's `versions` map. Truncating strings alone
#                        is not enough: those bodies are large because of their
#                        *shape*, not because of any one long string.
#   3. _fit           -- hard ceiling, a last resort that logs loudly
# --------------------------------------------------------------------------
MAX_BODY_CHARS = 2000
MAX_BODY_BYTES = 20_000
MAX_ITEMS = 25
MAX_VULNS = 50
VULN_SUMMARY_MAX = 15


def _truncate(text: str, n: int = MAX_BODY_CHARS) -> str:
    if not text:
        return text
    if len(text) <= n:
        return text
    return text[:n] + f"... [truncated, {len(text) - n} more chars]"


def _truncate_dict(obj, limit: int = MAX_BODY_CHARS):
    if isinstance(obj, str):
        return _truncate(obj, limit)
    if isinstance(obj, dict):
        return {k: _truncate_dict(v, limit) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_truncate_dict(v, limit) for v in obj]
    return obj


def _safe_json(r):
    try:
        data = r.json()
    except Exception:
        # Not JSON (gateway HTML, empty body, truncated response...)
        return {"_raw_text": _truncate(r.text)}
    return _truncate_dict(data)


def _json_size(obj) -> int:
    try:
        return len(json.dumps(obj))
    except Exception:
        return 0


def _fit(body, limit: int = MAX_BODY_BYTES):
    """Hard ceiling. Only reachable if a projection failed to shrink a body."""
    size = _json_size(body)
    if size <= limit:
        return body
    log.error("body still %d bytes after projection; hard-truncating to %d", size, limit)
    return {
        "_truncated": True,
        "_original_bytes": size,
        "preview": _truncate(json.dumps(body), 1000),
    }


# --- per-tool projections -------------------------------------------------
def _slim_github_search(body):
    """Keep only the fields the agent reads: full_name drives the whole walk."""
    if not isinstance(body, dict):
        return body
    items = body.get("items")
    if not isinstance(items, list):
        return body
    slim = []
    for item in items[:MAX_ITEMS]:
        if not isinstance(item, dict):
            continue
        slim.append({
            "full_name": item.get("full_name"),
            "language": item.get("language"),
            "stargazers_count": item.get("stargazers_count"),
            "pushed_at": item.get("pushed_at"),
            "default_branch": item.get("default_branch"),
        })
    return {
        "total_count": body.get("total_count"),
        "incomplete_results": body.get("incomplete_results"),
        "items": slim,
    }


def _slim_github_file(body):
    if not isinstance(body, dict):
        return body
    out = {
        k: body.get(k)
        for k in (
            "name",
            "path",
            "sha",
            "size",
            "encoding",
            "content_encoding",
            "content_truncated",
            "content_original_chars",
        )
        if k in body
    }
    out["content"] = body.get("content")
    return out


def _slim_pypi(body):
    """Drop `releases`/`urls`; the audit only needs info.version."""
    if not isinstance(body, dict):
        return body
    info = body.get("info") if isinstance(body.get("info"), dict) else {}
    releases = body.get("releases")
    return {
        "info": {
            "name": info.get("name"),
            "version": info.get("version"),
            "requires_python": info.get("requires_python"),
            "summary": _truncate(info.get("summary") or "", 300),
        },
        "release_count": len(releases) if isinstance(releases, dict) else None,
    }


def _slim_npm(body):
    """Drop `versions`; the audit only needs the package identity."""
    if not isinstance(body, dict):
        return body
    versions = body.get("versions")
    return {
        "name": body.get("name"),
        "dist-tags": body.get("dist-tags"),
        "description": _truncate(body.get("description") or "", 300),
        "version_count": len(versions) if isinstance(versions, dict) else None,
    }


def _slim_osv(body):
    """Keep every advisory id so the count stays exact, drop the prose."""
    if not isinstance(body, dict):
        return body
    found = body.get("vulns")
    if not isinstance(found, list):
        return body
    include_summary = len(found) <= VULN_SUMMARY_MAX
    slim = []
    for v in found[:MAX_VULNS]:
        if not isinstance(v, dict):
            continue
        entry = {"id": v.get("id"), "aliases": (v.get("aliases") or [])[:2]}
        if include_summary:
            entry["summary"] = _truncate(v.get("summary") or "", 120)
        slim.append(entry)
    return {"vulns": slim, "vuln_count": len(found)}


def _decode_b64(raw) -> Optional[str]:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return base64.b64decode(raw).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError, TypeError):
        return None


def _truncate_manifest_text(text: str, path: str = "", n: int = MAX_BODY_CHARS) -> tuple[str, bool]:
    """Truncate manifest text so the result is still parseable.

    Nothing is appended to the text: a trailing marker would make a TOML
    document invalid and kill the parse outright. For pyproject.toml the cut is
    taken at the last top-level table header, which keeps every included table
    complete. Returns (text, was_truncated).
    """
    if len(text) <= n:
        return text, False

    head = text[:n]
    if path.endswith(".toml"):
        starts = [m.start() for m in re.finditer(r"(?m)^\[", head)]
        if len(starts) > 1:
            head = head[: starts[-1]]
    else:
        cut = head.rfind("\n")
        if cut > n // 2:
            head = head[:cut]
    return head, True


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
    return {"status_code": r.status_code, "body": _fit(_slim_github_search(_safe_json(r)))}


@observe
def github_get_file(repo_full_name: str, path: str):
    """GET https://api.github.com/repos/{owner}/{repo}/contents/{path}

    GitHub returns file bodies base64-encoded, and a real manifest runs to
    megabytes. Storing that verbatim is what bloated a session to 14.8 MB, so
    the base64 is decoded here and only the manifest *text* is kept, truncated
    on a line boundary. ``decode_manifest`` reads it back through
    ``content_encoding``, so the dependency walk keeps working while the
    observed event stays small.
    """
    r = httpx.get(
        f"https://api.github.com/repos/{repo_full_name}/contents/{path}",
        headers=_github_headers(),
        timeout=config.HTTP_TIMEOUT,
    )
    try:
        body = r.json()
    except Exception:
        body = {"_raw_text": _truncate(r.text)}

    if isinstance(body, dict) and "content" in body:
        text = _decode_b64(body.get("content"))
        if text is None:
            body["content"] = "... [base64 omitted]"
            body["content_encoding"] = "omitted"
        else:
            head, truncated = _truncate_manifest_text(text, path)
            body["content"] = head
            body["content_encoding"] = "utf-8"
            if truncated:
                body["content_truncated"] = True
                body["content_original_chars"] = len(text)

    return {"status_code": r.status_code, "body": _fit(_slim_github_file(body))}


@observe
def pypi_get_metadata(package: str):
    """GET https://pypi.org/pypi/{package}/json

    The raw body carries every release ever published (hundreds of KB). Only
    the latest version is read downstream, so that is all that is kept.
    """
    r = httpx.get(f"https://pypi.org/pypi/{package}/json", timeout=config.HTTP_TIMEOUT)
    return {"status_code": r.status_code, "body": _fit(_slim_pypi(_safe_json(r)))}


@observe
def npm_get_metadata(package: str):
    """GET https://registry.npmjs.org/{package}

    The raw body carries every published version (often ~1 MB).
    """
    r = httpx.get(f"https://registry.npmjs.org/{package}", timeout=config.HTTP_TIMEOUT)
    return {"status_code": r.status_code, "body": _fit(_slim_npm(_safe_json(r)))}


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
    return {"status_code": r.status_code, "body": _fit(_slim_osv(_safe_json(r)))}


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
    """Return the manifest text from a GitHub contents response.

    ``github_get_file`` decodes the base64 itself and marks the body with
    ``content_encoding``, so the text path is checked first. A body that still
    carries raw base64 (any other caller) keeps working unchanged.
    """
    body = result.get("body")
    if not isinstance(body, dict):
        return None
    raw = body.get("content")
    if not raw:
        return None

    marker = body.get("content_encoding")
    if marker == "utf-8":
        # Already decoded text, possibly truncated on a line boundary.
        return raw
    if marker == "omitted":
        return None

    if body.get("encoding") not in (None, "base64"):
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

# A quoted PEP 508 requirement on its own line, as it appears inside a
# `dependencies = [ ... ]` array. Only used to recover a truncated pyproject.toml.
_QUOTED_SPEC_LINE = re.compile(
    r"""^\s*["'](?P<spec>[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?\s*(?:[<>=!~][^"']*)?)["']\s*,?\s*$"""
)


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
        # A body truncated mid-array is not valid TOML. Dependency entries are
        # quoted one-per-line inside `dependencies = [...]`, so they can still
        # be recovered rather than losing the whole manifest.
        log.info("pyproject.toml did not parse (%s); scanning for quoted specs", exc)
        specs = [
            m.group("spec")
            for m in (_QUOTED_SPEC_LINE.match(line) for line in text.splitlines())
            if m
        ]
        if not specs:
            log.warning("pyproject.toml yielded no parseable dependencies")
            return []
        return parse_requirements_txt("\n".join(specs))

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
