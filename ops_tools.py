"""Real tools for the Ops Digest witness.

A second, goal-directed witness in the same repository. Where RepoPulse was a
reporter with no stake, this one has a job to finish: gather real operational
data, then *deliver* a digest by writing it to a real GitHub issue.

Why that matters: its failure surface is auth, rate limits, 5xx and timeouts --
not "file not found". Those are the failures the wall is allowed to publish, and
they are the failures an agent is tempted to paper over when it must report a
finished job.

Tools are wrapped with @observe exactly like RepoPulse's, and run through
tools.guarded() so they share the same pacing, 403 detection and circuit
breakers. Bodies are capped with the same helpers so a session can never bloat.

Read-only sources and payload trimming only; the two write tools are the
delivery step.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import config  # noqa: F401  -- sets COGEXT_API_BASE before cogext_observe loads
import httpx
from cogext_observe import observe

from tools import _fit, _github_headers, _safe_json, _truncate, USER_AGENT

log = logging.getLogger("repopulse.ops_tools")


def _read_headers() -> dict:
    """Headers for the read-only sources.

    Reads are deliberately anonymous. Anonymous GitHub allows 60 core requests
    per hour per IP, which this watchlist genuinely exceeds -- so the agent runs
    against the same ceiling most developers actually run against, and the 403s
    it meets are real ones.

    Set GITHUB_READ_TOKEN to authenticate reads instead (5,000/hour).
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    }
    token = os.environ.get("GITHUB_READ_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


# What the digest covers. Two of the owner's own repositories plus the upstream
# repositories behind the stack's dependencies -- a real supply-chain watchlist.
# It is wide on purpose: the anonymous read budget is 60 requests/hour and a
# full pass needs more, so real rate limiting is part of the normal cycle.
WATCH_REPOS = (
    "yaminbinyoosuf/repopulse",
    "yaminbinyoosuf/cogext-backend",
    "fastapi/fastapi",
    "pydantic/pydantic",
    "encode/httpx",
    "encode/uvicorn",
    "tiangolo/sqlmodel",
    "sqlalchemy/sqlalchemy",
    "pallets/flask",
    "django/django",
    "psf/requests",
    "urllib3/urllib3",
    "aio-libs/aiohttp",
    "numpy/numpy",
    "pandas-dev/pandas",
    "scipy/scipy",
    "scikit-learn/scikit-learn",
    "pytest-dev/pytest",
    "python-poetry/poetry",
    "astral-sh/ruff",
    "psf/black",
    "python/mypy",
    "celery/celery",
    "redis/redis-py",
    "boto/boto3",
    "jupyter/notebook",
    "streamlit/streamlit",
    "pypa/pip",
    "pypa/setuptools",
    "psf/cachecontrol",
    "theskumar/python-dotenv",
    "openai/openai-python",
)
WATCH_PYPI = (
    "fastapi",
    "pydantic",
    "supabase",
    "httpx",
    "uvicorn",
    "slowapi",
    "resend",
    "python-dotenv",
)
WATCH_NPM = ("express", "axios", "zod")
STATUS_URLS = (
    "https://www.githubstatus.com/api/v2/status.json",
    "https://status.python.org/api/v2/status.json",
    "https://status.npmjs.org/api/v2/status.json",
)

# The delivery target: one issue, updated in place, found by title. Stateless --
# no database, no stored issue number.
DIGEST_TITLE = "Ops Witness — digest log"


# --------------------------------------------------------------------------
# read-only sources
# --------------------------------------------------------------------------
@observe
def github_repo(repo_full_name: str):
    """GET https://api.github.com/repos/{owner}/{repo}"""
    r = httpx.get(
        f"https://api.github.com/repos/{repo_full_name}",
        headers=_read_headers(),
        timeout=config.HTTP_TIMEOUT,
    )
    body = _safe_json(r)
    if isinstance(body, dict):
        body = {
            k: body.get(k)
            for k in ("full_name", "private", "open_issues_count", "stargazers_count",
                      "pushed_at", "default_branch", "archived")
        }
    return {"status_code": r.status_code, "body": _fit(body)}


@observe
def github_open_issues(repo_full_name: str, per_page: int = 5):
    """GET https://api.github.com/repos/{owner}/{repo}/issues"""
    r = httpx.get(
        f"https://api.github.com/repos/{repo_full_name}/issues",
        params={"state": "open", "sort": "created", "direction": "desc", "per_page": per_page},
        headers=_read_headers(),
        timeout=config.HTTP_TIMEOUT,
    )
    body = _safe_json(r)
    if isinstance(body, list):
        body = {
            "count": len(body),
            "items": [
                {
                    "number": i.get("number"),
                    "title": _truncate(i.get("title") or "", 120),
                    "created_at": i.get("created_at"),
                    "is_pull_request": "pull_request" in i,
                }
                for i in body[:per_page]
                if isinstance(i, dict)
            ],
        }
    return {"status_code": r.status_code, "body": _fit(body)}


@observe
def github_latest_run(repo_full_name: str):
    """GET https://api.github.com/repos/{owner}/{repo}/actions/runs"""
    r = httpx.get(
        f"https://api.github.com/repos/{repo_full_name}/actions/runs",
        params={"per_page": 1},
        headers=_read_headers(),
        timeout=config.HTTP_TIMEOUT,
    )
    body = _safe_json(r)
    if isinstance(body, dict):
        runs = body.get("workflow_runs") or []
        first = runs[0] if runs and isinstance(runs[0], dict) else {}
        body = {
            "total_count": body.get("total_count"),
            "latest": {
                "name": first.get("name"),
                "status": first.get("status"),
                "conclusion": first.get("conclusion"),
                "created_at": first.get("created_at"),
            },
        }
    return {"status_code": r.status_code, "body": _fit(body)}


@observe
def probe(url: str):
    """GET an upstream status page and record what it actually answered."""
    started = time.monotonic()
    try:
        r = httpx.get(url, timeout=config.HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT})
    except Exception as exc:
        return {
            "status_code": 0,
            "transport_error": True,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "body": {"error": f"{type(exc).__name__}: {exc}"},
        }
    elapsed = int((time.monotonic() - started) * 1000)
    body = _safe_json(r)
    if isinstance(body, dict):
        status = body.get("status") if isinstance(body.get("status"), dict) else None
        body = {
            "indicator": (status or {}).get("indicator"),
            "description": _truncate(str((status or {}).get("description") or ""), 120),
        }
    return {"status_code": r.status_code, "elapsed_ms": elapsed, "body": _fit(body)}


# --------------------------------------------------------------------------
# the delivery step: a real write to a real repository
# --------------------------------------------------------------------------
@observe
def github_find_issue(repo_full_name: str, title: str):
    """GET /repos/{owner}/{repo}/issues -- locate the digest issue by title."""
    r = httpx.get(
        f"https://api.github.com/repos/{repo_full_name}/issues",
        params={"state": "all", "per_page": 100},
        headers=_github_headers(),
        timeout=config.HTTP_TIMEOUT,
    )
    body = _safe_json(r)
    found = None
    if isinstance(body, list):
        for issue in body:
            if isinstance(issue, dict) and (issue.get("title") or "").strip() == title:
                found = {"number": issue.get("number"), "state": issue.get("state")}
                break
    return {"status_code": r.status_code, "body": _fit({"found": found})}


@observe
def github_create_issue(repo_full_name: str, title: str, body_text: str):
    """POST /repos/{owner}/{repo}/issues -- create the digest issue."""
    r = httpx.post(
        f"https://api.github.com/repos/{repo_full_name}/issues",
        headers=_github_headers(),
        json={"title": title, "body": body_text},
        timeout=config.HTTP_TIMEOUT,
    )
    return {"status_code": r.status_code, "body": _issue_result(r)}


@observe
def github_update_issue(repo_full_name: str, number: int, body_text: str):
    """PATCH /repos/{owner}/{repo}/issues/{number} -- update the digest in place."""
    r = httpx.patch(
        f"https://api.github.com/repos/{repo_full_name}/issues/{number}",
        headers=_github_headers(),
        json={"body": body_text},
        timeout=config.HTTP_TIMEOUT,
    )
    return {"status_code": r.status_code, "body": _issue_result(r)}


def _issue_result(r: httpx.Response) -> Any:
    body = _safe_json(r)
    if isinstance(body, dict):
        body = {
            k: body.get(k)
            for k in ("number", "html_url", "state", "updated_at", "title")
            if k in body
        }
    return _fit(body)
