"""Publishing to the COGEXT Square.

The live API, as read from https://api.cogextai.com/openapi.json:

  POST /api/v1/live/session          idempotent session create
  POST /api/v1/live/event            append one event; creates session on first write
  POST /api/v1/live/receipt          store a signed receipt
  POST /api/v1/live/publish          publish a session to the Square
  GET  /api/v1/live/square           the wall

A receipt on its own does **not** appear on the Square: the Square lists
sessions, and a session only becomes visible once it is published. So a catch
is published as (receipt + session), and nothing is published at all when there
is no signed receipt.

Wall hygiene is enforced here: de-duplication by tool+status, a hard cap of
three catches per cycle, severity ordering, and 404s skipped entirely.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional

import config
import httpx

log = logging.getLogger("repopulse.publish")

API_BASE = config.settings.cogext_api_url
HEADERS = {"User-Agent": "repopulse-sentinel/1.0"}

# tool+status pairs already published in this cycle
_seen: set[str] = set()
_published_count = 0


class Catch:
    """One candidate catch, with the verdict of the hygiene rules."""

    def __init__(self, receipt: dict, tier: Optional[int], reason: str = ""):
        self.receipt = receipt
        self.tier = tier
        self.reason = reason

    @property
    def key(self) -> str:
        status = (self.receipt.get("tool_response") or {}).get("http_status")
        return f"{self.receipt.get('tool')}:{status}"


def reset_dedupe() -> None:
    """Call at the start of each cycle."""
    global _published_count
    _seen.clear()
    _published_count = 0


def _post(path: str, payload: dict, timeout: float = 10.0) -> tuple[int, Any]:
    try:
        r = httpx.post(f"{API_BASE}{path}", json=payload, headers=HEADERS, timeout=timeout)
    except Exception as exc:
        log.error("POST %s failed: %s", path, exc)
        return 0, {"error": str(exc)}
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {"_raw_text": r.text[:300]}


def create_session(session_id: str) -> bool:
    """Idempotent. The observer calls this before its first tool."""
    status, body = _post("/live/session", {"session_id": session_id}, timeout=10.0)
    ok = status == 200
    if not ok:
        log.warning("session create for %s -> HTTP %s %s", session_id, status, str(body)[:200])
    return ok


def publish_session(session_id: str) -> bool:
    """Make a session visible on the Square. This is the wall write."""
    status, body = _post("/live/publish", {"session_id": session_id}, timeout=10.0)
    ok = status == 200
    if ok:
        log.info("published session %s to the Square", session_id)
    else:
        log.error("session publish for %s -> HTTP %s %s", session_id, status, str(body)[:200])
    return ok


def tier_for(receipt: dict) -> Optional[int]:
    """Severity tier, or None when the catch must never be published.

    0 = server error, 1 = auth/rate limit, 2 = timeout, 3 = other.
    Returns None for 404s, which are ordinary "file absent" answers rather
    than failures worth a place on the wall.
    """
    response = receipt.get("tool_response") or {}
    status = response.get("http_status")
    try:
        blob = json.dumps(response.get("body"))[:400].lower()
    except Exception:
        blob = ""

    if status == 404:
        return None
    if any(token in blob for token in ("timeout", "timed out", "connection")):
        return 2
    if isinstance(status, int) and status >= 500:
        return 0
    if status in (401, 403, 429):
        return 1
    return 3


def should_publish(receipt: dict) -> bool:
    """De-duplicate by tool+status within the cycle, and enforce the cap."""
    status = (receipt.get("tool_response") or {}).get("http_status")
    key = f"{receipt.get('tool')}:{status}"
    if key in _seen:
        log.info("skip duplicate catch %s", key)
        return False
    if _published_count >= config.MAX_CATCHES_PER_CYCLE:
        log.warning("cycle catch cap (%d) reached; not publishing %s", config.MAX_CATCHES_PER_CYCLE, key)
        return False
    return True


def _too_large(receipt: dict) -> Optional[int]:
    try:
        size = len(json.dumps(receipt).encode())
    except Exception:
        return None
    return size if size > config.MAX_RECEIPT_BYTES else None


def publish(receipt: dict) -> bool:
    """Publish one signed receipt. Returns True only on HTTP 200."""
    global _published_count

    if not should_publish(receipt):
        return False

    oversize = _too_large(receipt)
    if oversize:
        log.error(
            "receipt %s is %d bytes (> %d); refusing to send it to the backend",
            receipt.get("receipt_id"),
            oversize,
            config.MAX_RECEIPT_BYTES,
        )
        return False

    status, body = _post("/live/receipt", receipt, timeout=10.0)
    if status != 200:
        log.error(
            "receipt %s rejected: HTTP %s %s",
            receipt.get("receipt_id"),
            status,
            str(body)[:200],
        )
        return False

    _seen.add(f"{receipt.get('tool')}:{(receipt.get('tool_response') or {}).get('http_status')}")
    _published_count += 1
    log.info(
        "receipt %s published (tool=%s status=%s)",
        receipt.get("receipt_id"),
        receipt.get("tool"),
        (receipt.get("tool_response") or {}).get("http_status"),
    )
    return True


def verify_receipt_stored(receipt_id: str) -> bool:
    """GET /live/receipt/{id} -- confirms the backend really kept it."""
    return verify_receipt_on_wall(receipt_id)["stored"]


# The /r/<id> page verifies entirely in the browser:
#   secretBytes = 'cogext-observe-receipt-v1'
#   canonical JSON (sorted keys, no whitespace) over exactly eight fields
#   HMAC-SHA256
# Reproducing that here is what makes "will this receipt show VALID in the
# browser?" answerable in CI.
BROWSER_SIGNING_KEY = "cogext-observe-receipt-v1"
SIGNED_FIELDS = (
    "receipt_id",
    "session_id",
    "tool",
    "tool_response",
    "agent_claim",
    "verdict",
    "reason",
    "recorded_at",
)


def browser_canonical(receipt: dict) -> Optional[str]:
    try:
        payload = {k: receipt[k] for k in SIGNED_FIELDS}
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
    except Exception:
        return None


def verify_receipt_on_wall(receipt_id: str) -> dict:
    """Fetch a stored receipt and reproduce the browser's verification.

    Note: ``cogext_observe.receipt.verify_receipt`` cannot be used on a fetched
    receipt. It hashes every field except signature/verify_url, and the backend
    adds ``published`` and ``created_at``, so it reports INVALID on a receipt
    the browser shows as VALID. The page names the signed fields explicitly,
    and so does this.
    """
    result = {
        "stored": False,
        "browser_valid": False,
        "computed": None,
        "stored_signature": None,
        "note": None,
    }
    try:
        r = httpx.get(f"{API_BASE}/live/receipt/{receipt_id}", timeout=10.0)
    except Exception as exc:
        result["note"] = f"lookup failed: {exc}"
        return result
    if r.status_code != 200:
        result["note"] = f"HTTP {r.status_code}"
        return result
    try:
        stored = r.json()
    except Exception:
        result["note"] = "unparseable response"
        return result

    result["stored"] = bool(stored)
    result["stored_signature"] = str(stored.get("signature") or "")
    canonical = browser_canonical(stored)
    if canonical is None:
        result["note"] = "missing signed fields"
        return result
    import hashlib
    import hmac

    computed = hmac.new(
        BROWSER_SIGNING_KEY.encode(), canonical.encode(), hashlib.sha256
    ).hexdigest()
    result["computed"] = computed
    result["browser_valid"] = computed == result["stored_signature"].lower()
    if not config.settings.receipt_key_is_default:
        result["note"] = (
            "COGEXT_RECEIPT_KEY is set, so receipts are signed with a key the "
            "browser does not use; /r/<id> will show INVALID"
        )
    return result
