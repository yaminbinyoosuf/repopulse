"""The RepoPulse Sentinel agent.

Reads real manifests from real repositories, checks real package indexes and
the real OSV database, and reports honestly whether its own summary matches
what the tools actually returned.
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Optional

import config
import tools

log = logging.getLogger("repopulse.agent")

# `sort` is a parameter of the search endpoint, not a search qualifier.
GITHUB_QUERY = "language:python stars:>100"


def new_session_id() -> str:
    """Every session this agent creates carries the witness- label."""
    return f"witness-{uuid.uuid4().hex[:8]}"


def bind_observer_session(session_id: str) -> bool:
    """Point cogext-observe's internal session at our session id.

    The @observe decorator calls ``log_event(get_session(), ...)`` for every
    tool call, and ``get_session()`` returns a random hex id on first use. That
    id has no ``witness-`` label, so the events of this agent would land in an
    unlabelled session while the receipts carried a labelled one -- two
    different sessions for one cycle, and an unlabelled session on the wall.

    Setting the module's id before the first tool call keeps events and
    receipts in one session that is honestly labelled. It touches nothing but
    this process's own state; no backend code is modified.
    """
    try:
        import cogext_observe.session as observer_session

        observer_session._session_id = session_id
        return True
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("could not bind observer session id: %s", exc)
        return False


# --------------------------------------------------------------------------
# audit
# --------------------------------------------------------------------------
def collect_findings() -> tuple[list[dict], list[str], bool]:
    """Walk repos -> manifests -> dependencies -> PyPI -> OSV.

    Returns (findings, notes, blocked). ``blocked`` is True when a rate limit or
    an open circuit breaker stopped the walk early.
    """
    findings: list[dict] = []
    notes: list[str] = []
    state = {"blocked": False}

    def call(name: str, fn, *args):
        try:
            return tools.guarded(name, fn, *args)
        except (tools.RateLimitHit, tools.CircuitOpen) as exc:
            state["blocked"] = True
            notes.append(f"{name}: {exc}")
            log.warning("stopping walk: %s", exc)
            return None

    repos = call("github_search_repos", tools.github_search_repos, GITHUB_QUERY)
    if repos is None:
        return findings, notes, True
    if repos["status_code"] != 200:
        notes.append(f"github_search_repos HTTP {repos['status_code']}")
        return findings, notes, False

    body = repos["body"] if isinstance(repos["body"], dict) else {}
    items = body.get("items") or []
    if not items:
        notes.append("github_search_repos returned HTTP 200 with an empty items list")
        return findings, notes, False

    log.info("github search returned %d candidate repositories", len(items))

    audited = 0
    for repo in items:
        if audited >= config.MAX_REPOS:
            break
        full_name = repo.get("full_name")
        if not full_name:
            continue

        manifest = None
        for path in tools.MANIFEST_PATHS:
            result = call("github_get_file", tools.github_get_file, full_name, path)
            if result is None:
                break
            if result["status_code"] == 200:
                result["path"] = path
                manifest = result
                break

        if manifest is None:
            if not state["blocked"]:
                notes.append(f"{full_name}: no readable manifest")
            if state["blocked"]:
                break
            continue

        deps = tools.parse_dependencies(manifest)
        if not deps:
            notes.append(f"{full_name}: {manifest['path']} yielded no parseable dependencies")
            continue

        audited += 1
        log.info(
            "%s: %s -> %d dependencies (repository %d/%d)",
            full_name,
            manifest["path"],
            len(deps),
            audited,
            config.MAX_REPOS,
        )

        for dep in deps[: config.MAX_DEPS_PER_REPO]:
            meta = call("pypi_get_metadata", tools.pypi_get_metadata, dep["name"])
            if meta is None:
                break
            vulns = call("osv_query", tools.osv_query, dep["name"], dep["version"], "PyPI")
            if vulns is None:
                break
            findings.append(
                {
                    "repo": full_name,
                    "manifest_path": manifest["path"],
                    "manifest_status": manifest["status_code"],
                    "dep": dep,
                    "meta": meta,
                    "vulns": vulns,
                }
            )

        if state["blocked"]:
            break

    return findings, notes, state["blocked"]


def observed_http_statuses() -> list[int]:
    return [
        c["http_status"]
        for c in _recent_calls()
        if isinstance(c.get("http_status"), int)
    ]


def _recent_calls() -> list[dict]:
    from cogext_observe.decorator import get_recent_calls

    return get_recent_calls()


# --------------------------------------------------------------------------
# wall protection: only publish a claim that really was a claim
# --------------------------------------------------------------------------
FAILURE_MARKERS = (
    "fail",
    "error",
    "unavailable",
    "unable",
    "could not",
    "couldn't",
    "cannot",
    "can't",
    "not available",
    "missing",
    "not found",
    "denied",
    "unauthorized",
    "forbidden",
    "timed out",
    "timeout",
    "rate limit",
    "rate-limit",
    "exceeded",
    "skipped",
    "no data",
    "inconclusive",
    "incomplete",
    "partial",
    "unverified",
    "not verified",
    "unknown",
    "unreachable",
    "absent",
    "404",
    "403",
    "429",
    "500",
    "502",
    "503",
    "504",
)

_TOOL_ALIASES = {
    "github_search_repos": ("github", "search", "repositories", "repo list"),
    "github_get_file": ("github", "manifest", "requirements.txt", "pyproject", "file"),
    "pypi_get_metadata": ("pypi", "metadata", "package index"),
    "npm_get_metadata": ("npm", "registry"),
    "osv_query": ("osv", "vulnerab", "advisor", "advisories"),
}

_COUNT_FAILURE = re.compile(
    r"\b(?:\d+|one|two|three|four|five|six|several|some|multiple|most|many)\b"
    r"(?:\s+of\s+(?:the\s+)?(?:\d+\s+)?)?\s*"
    r"(?:lookups?|calls?|queries|requests?|checks?|dependencies|packages|"
    r"repositories|repos|tools|operations|fetches|manifests?)"
    r"[^.]{0,50}?"
    r"\b(?:fail|failed|failing|error|errored|unavailable|missing|timed out|"
    r"timeout|skipped|exceeded|unreachable)",
    re.IGNORECASE,
)


def disclosure_of_failure(summary_text: str, mismatch: dict) -> Optional[str]:
    """Return the sentence in which the agent itself discloses the failure.

    ``detect_mismatch`` fires on keyword overlap: if the summary contains any
    success-flavoured word it is treated as a success claim, even when the same
    summary plainly reports the failure. A receipt produced that way would put a
    false MISMATCH on the wall -- the agent never claimed success, so there is
    nothing to catch.

    The test is deliberately narrow, and strictly about *this* failure:

    1. a sentence naming the failing service/domain alongside a failure marker,
       or
    2. a sentence reporting an aggregate count of failed operations
       ("3 of the 15 lookups failed").

    Anything else leaves the claim standing. A disclosure about one service does
    not excuse an undisclosed failure in another -- suppressing those would
    throw away real catches.
    """
    tool = mismatch.get("tool") or ""
    # Accept the tool's own name in every form a report actually uses it:
    # github_open_issues, "github open issues", "github-open-issues". Without
    # this, a disclosure that names the tool literally is not recognised, and a
    # false MISMATCH receipt is published for a failure the agent did report.
    aliases = set(_TOOL_ALIASES.get(tool, ()))
    aliases.update(
        {
            tool,
            tool.replace("_", " "),
            tool.replace("_", "-"),
            tool.replace("_", ""),
        }
    )
    aliases = tuple(a.lower() for a in aliases if a)

    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", summary_text) if s.strip()]

    # 1. domain-specific disclosure
    for sentence in sentences:
        low = sentence.lower()
        if not any(marker in low for marker in FAILURE_MARKERS):
            continue
        if any(alias in low for alias in aliases):
            return sentence

    # 2. aggregate disclosure of failed operations
    for sentence in sentences:
        if _COUNT_FAILURE.search(sentence):
            return sentence

    return None
