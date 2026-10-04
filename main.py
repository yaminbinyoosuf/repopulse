"""RepoPulse Sentinel -- entry point and cycle.

    python main.py --once            one cycle, publishes real catches
    python main.py --once --dry-run  one cycle, makes real calls, publishes nothing
    python main.py --loop            cycle every --interval seconds (default 900)

One cycle: trending Python repositories -> dependency manifests -> PyPI
metadata -> OSV advisories -> an LLM summary -> cogext-observe compares that
summary against what the tools actually returned -> genuine mismatches become
signed receipts and are published to the COGEXT Square.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from typing import Optional

import config  # noqa: F401  -- must be imported first; sets COGEXT_API_BASE

import agent
import publish
import summary
import tools
from cogext_observe.decorator import get_recent_calls
from cogext_observe.detector import detect_mismatch
from cogext_observe.receipt import generate_receipt, verify_receipt

log = logging.getLogger("repopulse")

SQUARE_URL = "https://cogextai.com/square"


def setup_logging(verbose: bool = False) -> None:
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
    logging.basicConfig(
        level=level,
        format=fmt,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(config.LOG_DIR / "repopulse.log", encoding="utf-8"),
        ],
        force=True,
    )
    # httpx logs every request at INFO; keep that for -v and use our own
    # per-tool trace otherwise.
    logging.getLogger("httpx").setLevel(logging.INFO if verbose else logging.WARNING)


def run_cycle(dry_run: bool = False) -> dict:
    """One full audit cycle. Returns a report dict."""
    report: dict = {
        "session_id": None,
        "dry_run": dry_run,
        "repos_seen": 0,
        "findings": 0,
        "tool_calls": 0,
        "call_tally": {},
        "failures": [],
        "notes": [],
        "summary": None,
        "mismatch": False,
        "candidates": [],
        "unpublished_reasons": [],
        "suppressed_disclosures": [],
        "suppressions": 0,
        "receipts": [],
        "session_published": False,
        "outcome": None,
    }

    tools.reset_guards()
    publish.reset_dedupe()

    if dry_run:
        # A true rehearsal: suppress cogext-observe's own event writes so a dry
        # run does not touch the backend at all. In-process mismatch detection
        # is unaffected -- the decorator still records recent calls.
        os.environ["COGEXT_OBSERVE_LOCAL"] = "1"

    session_id = agent.new_session_id()
    report["session_id"] = session_id
    log.info("cycle start | session %s | dry_run=%s", session_id, dry_run)

    # Label first, then create: events and receipts must share one session.
    agent.bind_observer_session(session_id)
    if dry_run:
        log.info("dry run: not creating the session on the backend")
    elif not publish.create_session(session_id):
        report["outcome"] = "could not create session on the backend; nothing published"
        return report

    findings, notes, blocked = agent.collect_findings()
    report["notes"] = notes
    report["findings"] = len(findings)
    report["repos_seen"] = len({f["repo"] for f in findings})
    report["rate_limited_or_blocked"] = blocked
    report["call_tally"] = tools.call_tally()
    report["tool_calls"] = len(tools.call_log())
    report["failures"] = [
        {"tool": c["tool"], "status": c["status"]} for c in tools.failures()
    ]

    log.info("tool calls this cycle: %s", report["call_tally"])
    for note in notes:
        log.info("note: %s", note)

    if not findings:
        report["outcome"] = "no findings collected; nothing to summarize or publish"
        log.warning(report["outcome"])
        return report

    # --- the agent writes what it believes happened -------------------------
    try:
        summary_text = summary.generate_summary(findings)
    except summary.LLMUnavailable as exc:
        report["outcome"] = f"LLM unavailable, refusing to invent a summary: {exc}"
        report["error"] = True
        log.error(report["outcome"])
        return report
    except summary.LLMError as exc:
        report["outcome"] = f"LLM call failed: {exc}"
        report["error"] = True
        log.error(report["outcome"])
        return report

    report["summary"] = summary_text
    log.info("agent summary: %s", summary_text.replace("\n", " ")[:400])

    # --- cogext-observe compares the claim against the real calls ----------
    # detect_mismatch only ever inspects recent_calls[0]. Running the same real
    # detector across the window is what the brief's own safeguards assume:
    # de-duplication, a cap of three catches and severity ordering mean nothing
    # when there is only ever one candidate, and it is the only way a real
    # overclaim about an earlier failure can be caught at all. The detector
    # itself is untouched -- it is simply applied to each failed call.
    recent = get_recent_calls()
    failed_calls = [c for c in recent if c.get("failure")]

    candidates = []
    for index, call in enumerate(recent):
        if not call.get("failure"):
            continue
        mismatch = detect_mismatch(summary_text, recent[index:])
        if not mismatch:
            continue
        candidates.append(
            {
                "tool": mismatch["tool"],
                "http_status": (mismatch.get("tool_response") or {}).get("http_status"),
                "tier": publish.tier_for(mismatch),
                "mismatch": mismatch,
            }
        )

    report["mismatch"] = bool(candidates)
    report["candidates"] = [
        {"tool": c["tool"], "http_status": c["http_status"], "tier": c["tier"]}
        for c in candidates
    ]
    log.info(
        "cogext-observe: %d failed call(s) in the window -> %d candidate mismatch(es)",
        len(failed_calls),
        len(candidates),
    )

    if not candidates:
        report["outcome"] = "no mismatch: the summary matches the observed tool results"
        return report

    # Wall hygiene. Drop 404s, and drop the detector's false positives: if the
    # agent disclosed the failure itself then it never claimed success, and
    # publishing that would be a MISMATCH receipt for a claim nobody made.
    publishable = []
    for cand in candidates:
        if cand["tier"] is None:
            report["unpublished_reasons"].append(
                f"{cand['tool']}:{cand['http_status']} skipped -- 404 is an ordinary answer"
            )
            continue
        disclosure = agent.disclosure_of_failure(summary_text, cand["mismatch"])
        if disclosure:
            report["suppressions"] += 1
            report["suppressed_disclosures"].append(
                {
                    "tool": cand["tool"],
                    "http_status": cand["http_status"],
                    "disclosure": disclosure,
                }
            )
            report["unpublished_reasons"].append(
                f"{cand['tool']}:{cand['http_status']} suppressed -- the summary discloses the failure"
            )
            log.warning(
                "suppressed %s:%s -- the summary discloses the failure: %s",
                cand["tool"],
                cand["http_status"],
                disclosure,
            )
            continue
        publishable.append(cand)

    if not publishable:
        report["outcome"] = (
            "no publishable catch: every candidate was a 404 or was disclosed by the summary"
        )
        return report

    # 5xx first, then auth/rate limit, then timeouts.
    publishable.sort(key=lambda c: c["tier"])
    selected = publishable[: config.MAX_CATCHES_PER_CYCLE]
    if len(publishable) > len(selected):
        report["unpublished_reasons"].append(
            f"{len(publishable) - len(selected)} catch(es) dropped by the "
            f"{config.MAX_CATCHES_PER_CYCLE}-per-cycle cap"
        )

    for cand in selected:
        receipt = generate_receipt(cand["mismatch"], session_id)
        signature_ok = verify_receipt(receipt)
        entry = {
            "receipt_id": receipt["receipt_id"],
            "tool": receipt["tool"],
            "http_status": (receipt.get("tool_response") or {}).get("http_status"),
            "tier": cand["tier"],
            "agent_claim": receipt["agent_claim"],
            "verify_url": receipt["verify_url"],
            "signature_valid": signature_ok,
            "stored": False,
            "browser_valid": False,
            "published": False,
        }
        report["receipts"].append(entry)
        log.info(
            "candidate catch tier %s: tool=%s status=%s signature=%s",
            cand["tier"],
            receipt["tool"],
            entry["http_status"],
            "valid" if signature_ok else "INVALID",
        )

        if dry_run:
            continue

        if not publish.publish(receipt):
            report["unpublished_reasons"].append(
                f"{entry['tool']}:{entry['http_status']} not accepted by the backend"
            )
            continue

        entry["published"] = True
        check = publish.verify_receipt_on_wall(receipt["receipt_id"])
        entry["stored"] = check["stored"]
        entry["browser_valid"] = check["browser_valid"]
        if check.get("note"):
            entry["verify_note"] = check["note"]
        if not check["browser_valid"]:
            log.error(
                "receipt %s is stored but would NOT verify in the browser (%s)",
                receipt["receipt_id"],
                check.get("note") or "signature mismatch",
            )

    published = [r for r in report["receipts"] if r["published"]]

    if dry_run:
        report["outcome"] = (
            f"dry run: {len(report['receipts'])} receipt(s) generated and signed, nothing published"
        )
        return report

    if not published:
        report["outcome"] = "no receipt was accepted by the backend"
        return report

    # A session only reaches the Square once published, and only a cycle that
    # published a real receipt has anything to show there.
    report["session_published"] = publish.publish_session(session_id)
    report["outcome"] = f"published {len(published)} real catch(es)"
    return report


def print_report(report: dict) -> None:
    line = "=" * 72
    print(f"\n{line}\nREPOPULSE SENTINEL -- CYCLE REPORT\n{line}")
    print(f"session_id      : {report['session_id']}")
    print(f"dry_run         : {report['dry_run']}")
    print(f"tool calls      : {report['tool_calls']}  {report['call_tally']}")
    print(f"failures seen   : {report['failures'] or 'none'}")
    print(f"repos with data : {report['repos_seen']}")
    print(f"findings        : {report['findings']} dependency checks")
    if report.get("notes"):
        print("notes           :")
        for note in report["notes"]:
            print(f"  - {note}")
    if report.get("summary"):
        print(f"agent summary   :\n  {report['summary']}")
    print(f"candidates      : {report.get('candidates') or 'none'}")
    print(f"mismatch        : {report['mismatch']}")
    print(f"suppressions    : {report.get('suppressions', 0)}")
    for s in report.get("suppressed_disclosures", []):
        print(f"  suppressed {s['tool']}:{s['http_status']} -- {s['disclosure']}")
    for reason in report.get("unpublished_reasons", []):
        print(f"  not published: {reason}")
    print(f"outcome         : {report['outcome']}")
    if report["receipts"]:
        print("receipts        :")
        for r in report["receipts"]:
            print(
                f"  {r['verify_url']}\n"
                f"    tool={r['tool']} http_status={r['http_status']} tier={r.get('tier')} "
                f"signature={'valid' if r['signature_valid'] else 'INVALID'} "
                f"stored={r['stored']} browser={'VALID' if r.get('browser_valid') else 'INVALID'} "
                f"published={r['published']}"
            )
            if r.get("verify_note"):
                print(f"    note: {r['verify_note']}")
            print(f"    agent_claim: {r['agent_claim']}")
    if not report["receipts"]:
        print("receipts        : none produced this cycle")
    print(f"session on wall : {report['session_published']}")
    print(f"wall            : {SQUARE_URL}")
    print(line)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="RepoPulse Sentinel")
    parser.add_argument("--once", action="store_true", help="run exactly one cycle (default)")
    parser.add_argument("--loop", action="store_true", help="run continuously")
    parser.add_argument(
        "--interval", type=int, default=900, help="seconds between cycles in --loop mode"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="make real API calls but publish nothing to COGEXT",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    setup_logging(args.verbose)
    log.info("RepoPulse Sentinel starting")
    for key, value in config.settings.describe().items():
        log.info("config %s: %s", key, value)

    if not config.settings.has_llm:
        log.error(
            "no LLM API key found (DEEPSEEK_API_KEY, "
            "or OPENAI_API_KEY / GROQ_API_KEY as fallbacks). "
            "Refusing to run: there is no honest way to produce the summary, and a "
            "hardcoded one would invent a mismatch that never happened."
        )
        return 2

    if config.settings.observe_local and not args.dry_run:
        log.error(
            "COGEXT_OBSERVE_LOCAL=1 is set, which makes cogext-observe skip all "
            "publishing. Refusing to run a real cycle that would silently do nothing. "
            "Unset it, or use --dry-run if that is what you intended."
        )
        return 2

    if not args.loop:
        report = run_cycle(dry_run=args.dry_run)
        print_report(report)
        return 1 if report.get("error") else 0

    log.info("loop mode: every %d seconds", args.interval)
    exit_code = 0
    while True:
        try:
            report = run_cycle(dry_run=args.dry_run)
            print_report(report)
            exit_code = 1 if report.get("error") else 0
        except KeyboardInterrupt:
            log.info("interrupted, stopping")
            return exit_code
        except Exception as exc:  # a bad cycle must not kill the loop
            log.exception("cycle raised: %s", exc)
            exit_code = 1
        try:
            time.sleep(args.interval)
        except KeyboardInterrupt:
            log.info("interrupted, stopping")
            return exit_code


if __name__ == "__main__":
    sys.exit(main())
