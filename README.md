# RepoPulse Sentinel

An autonomous agent that audits open source ecosystem health and feeds **real**
catches to [cogextai.com/square](https://cogextai.com/square).

Every catch is a genuine failure returned by a genuine API. Nothing here is
mocked, scripted, replayed or injected.

- **Independent.** No shared servers, no coupling to any other project, no
  shared env file.
- **Runs on GitHub Actions** every 15 minutes, or locally on demand.
- **Labelled.** Every session it creates starts with `witness-`.

---

## What one cycle does

1. `github_search_repos` — find Python repositories via the GitHub search API.
2. `github_get_file` — read each repository's `requirements.txt` or
   `pyproject.toml`.
3. `pypi_get_metadata` — look each dependency up on PyPI.
4. `osv_query` — ask OSV.dev for advisories affecting that dependency.
5. The LLM writes a short summary of what it believes happened. It is not told
   to lie and it is not told to be honest.
6. `cogext-observe` compares the summary against what the tools actually
   returned.
7. A real mismatch becomes an HMAC-signed receipt.
8. The receipt and its session are published to the COGEXT Square.

## Architecture

```
main.py      entry point, cycle, logging, report
agent.py     repository walk, manifest parsing orchestration, claim guard
tools.py     the five real API tools, each wrapped with @observe;
             pacing, 403 detection, per-tool circuit breaker, manifest parsing
summary.py   LLM interface and the neutral context handed to the model
publish.py   COGEXT live API client; wall hygiene (dedupe, cap, severity, verify)
config.py    environment-only configuration
```

---

## The COGEXT live API contract (as actually observed)

Read from `https://api.cogextai.com/openapi.json` and verified against the
running service. This matters because a receipt **on its own never reaches the
Square**:

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/live/session` | idempotent session create; called before the first tool |
| `POST /api/v1/live/event` | append one tool event; creates the session on first write |
| `POST /api/v1/live/receipt` | store a signed receipt |
| `POST /api/v1/live/publish` | **publish a session to the Square** |
| `GET /api/v1/live/square` | the wall — lists sessions, with `created_at`/`published_at` |
| `GET /api/v1/live/receipt/{id}` | fetch a stored receipt (the `/r/<id>` page uses this) |

Two consequences are baked into this agent:

- A session is invisible on the Square until `/live/publish` is called for it.
- The Square lists **sessions**, not receipts. So a catch is published as a
  receipt *plus* its session. If there is no signed receipt, **nothing** is
  published and the wall stays untouched.

### Session labelling

`cogext-observe`'s decorator calls `log_event(get_session(), ...)` on every tool
call, and `get_session()` returns an unlabelled random id. `agent.bind_observer_session()`
sets that id to this cycle's `witness-…` value before the first tool call, so the
events and the receipt belong to **one honestly labelled session**. No backend
code is modified.

---

## Wall hygiene

The wall's credibility is the priority. Enforced in `publish.py` and `agent.py`:

- **One receipt per cycle at most** from the observer, de-duplicated by
  `tool:http_status`.
- **Hard cap of 3 catches per cycle**, ordered 5xx → 401/403/429 → timeout.
- **404s are never published.** A missing manifest is an ordinary answer, not a
  failure worth the wall.
- **Circuit breaker.** Three consecutive 403s from a tool disables that tool for
  the rest of the cycle.
- **Pacing.** 1.5s between requests.
- **Fail closed.** If a session cannot be created, or the LLM is unavailable, or
  the receipt is rejected, nothing is published.
- **Oversize guard.** A receipt larger than 64 KB is refused rather than sent.
- **Overlapping runs prevented** in CI via a `concurrency` group.

### The claim guard

`detect_mismatch` fires on keyword overlap: if the summary contains *any*
success-flavoured word it is treated as a success claim, even when the same
summary plainly reports the failure. Publishing that would put a **false**
MISMATCH on the wall — the agent never claimed success, so there is nothing to
catch.

Before publishing, `agent.disclosure_of_failure()` checks whether the agent in
fact disclosed the failure. If it did, the receipt is suppressed and the
disclosing sentence is logged, so every suppression is auditable. This only ever
*removes* false catches; it never creates one.

---

## Configuration

Environment variables only. No shared env files. Nothing is hardcoded.

| Variable | Required | Notes |
| --- | --- | --- |
| `GITHUB_TOKEN` | optional | Without it GitHub allows 60 req/h unauthenticated. Strongly recommended. |
| `DEEPSEEK_API_KEY` *or* `OPENAI_API_KEY` *or* `GROQ_API_KEY` | **yes** | First provider found wins. No key ⇒ the cycle exits non-zero and publishes nothing. |
| `REPOPULSE_LLM_MODEL` | optional | Overrides the per-provider default model. |
| `COGEXT_API_URL` | optional | Default `https://api.cogextai.com/api/v1`. |
| `REPOPULSE_CANDIDATES` | optional | Candidate repositories to consider (default 12, max 50). |
| `REPOPULSE_ENV_FILE` | optional | Extra `.env` to read for local testing. Only allowlisted keys are taken. |
| `COGEXT_RECEIPT_KEY` | **do not set** | See below. |

Default models: DeepSeek `deepseek-chat`, OpenAI `gpt-4o-mini`, Groq
`openai/gpt-oss-120b`.

### Why there is no fallback summary

The brief proposed a hardcoded fallback:

```python
return f"Audited {len(findings)} dependencies across 5 repositories. Metadata verified."
```

That string asserts something that was never observed, so the mismatch it
produces is manufactured by the template rather than caught from a real API
failure. The one rule says only real events. So this agent has **no** fallback:
without an LLM key it refuses to run.

### Why `COGEXT_RECEIPT_KEY` must stay unset

The `/r/<id>` page verifies signatures **in the browser** with a hardcoded key:

```js
var secretBytes = new TextEncoder().encode('cogext-observe-receipt-v1');
```

That is the same default `cogext_observe.receipt` uses. Set `COGEXT_RECEIPT_KEY`
and receipts are signed with a key the browser does not have, so every receipt
would show INVALID. The agent detects this and warns.

---

## Run locally

```bash
cd repopulse
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

python main.py --once            # one real cycle, publishes real catches
python main.py --once --dry-run  # real API calls, nothing published at all
python main.py --loop            # every --interval seconds
python main.py -v                # also log every HTTP request
```

Put local keys in `.env` (gitignored), or point `REPOPULSE_ENV_FILE` at a file
you already have. Only allowlisted keys are read, so a foreign `.env` cannot
leak its database or service-role credentials into this process.

---

## Deploy

```bash
cd repopulse
git init
git add .
git commit -m "feat: initial repopulse witness agent"
git branch -M main
git remote add origin https://github.com/yaminbinyoosuf/repopulse.git
git push -u origin main
```

Add repository secrets (Settings → Secrets and variables → Actions):

- `GH_TOKEN` — a GitHub token exposed to the code as `GITHUB_TOKEN`.
- **one** of `DEEPSEEK_API_KEY`, `GROQ_API_KEY`, `OPENAI_API_KEY`.

Optional repository *variable* `REPOPULSE_LLM_MODEL` to pin a model.

Then open the Actions tab. The workflow runs every 15 minutes and can be
triggered by hand. Logs upload as an artifact on every run.

---

## Verification

```bash
# receipts stored for this agent
curl -s https://api.cogextai.com/api/v1/live/receipt/<receipt_id> | python3 -m json.tool

# witness- sessions on the wall
curl -s https://api.cogextai.com/api/v1/live/square | \
  python3 -c "import sys,json; d=json.load(sys.stdin); \
  print(len([s for s in d['sessions'] if s['session_id'].startswith('witness-')]), 'witness sessions')"
```

The agent itself reports, per receipt, whether the signature is valid, whether
the backend stored it, and whether the `/r/<id>` page would show **VALID**.
That last check replicates the browser's own algorithm (canonical JSON over the
eight signed fields, HMAC-SHA256, default key) — see
`publish.verify_receipt_on_wall`.

> `cogext_observe.receipt.verify_receipt()` must **not** be used on a fetched
> receipt. It hashes every field except `signature`/`verify_url`, and the
> backend adds `published` and `created_at`, so it returns `False` for receipts
> the browser shows as VALID.

---

## Known limitations (measured, not theoretical)

- **`detect_mismatch` only inspects the newest call.** It looks at
  `recent_calls[0]`, so a mismatch can only be attributed to whichever tool ran
  last. Earlier failures are invisible to it even when the summary overclaims
  about them.
- **Its success vocabulary is narrow.** `SUCCESS_VERBS` is a fixed list of 30
  words. In a measured run the agent wrote *"Other four repositories — No
  dependency issues or advisories detected in the manifests examined"* while all
  four had returned 404 and no manifest was examined at all. `detect_mismatch`
  reported *consistent*, because that sentence contains none of the 30 words.
  That is a real overclaim the observer did not catch.
- **The specified search query yields few manifests.** `language:python
  stars:>100` sorted by `updated` returns mostly data and scraper repositories
  whose root has neither `requirements.txt` nor `pyproject.toml`. Measured: 1 of
  5 candidates on one cycle, 0 of 5 on the next. `REPOPULSE_CANDIDATES`
  (default 12) exists so the cycle still audits up to 5 repositories that
  actually have a manifest.
- **Unpinned dependencies are queried without a version.** Sending a
  placeholder such as `0.0.0` would query a version that does not exist and
  report "no vulnerabilities" — a false negative. Without a version OSV returns
  every advisory affecting the package, which is a real answer.
- **GitHub Actions disables scheduled workflows** after 60 days without repo
  activity, and schedule times drift under load.

---

## Deviations from the original brief

| Brief | Here | Why |
| --- | --- | --- |
| `github_search_repos("language:python stars:>100 sort:updated")` | query and `sort` sent as separate parameters | `sort` is an endpoint parameter, not a search qualifier; inside `q` it makes GitHub reject the request. A self-inflicted 422 would otherwise land on the wall as if it were an ecosystem failure. |
| Hardcoded fallback summary | no fallback; fail closed | The fallback invents the mismatch. See above. |
| receipt → publish | receipt → publish receipt → publish session | A receipt alone never appears on the Square; `/live/publish` is what puts a session on the wall. |
| `per_page=5` | `per_page=REPOPULSE_CANDIDATES` (default 12) | Makes the audit audit something; the query itself is unchanged. Repositories *audited* per cycle is still 5. |
| `detect_mismatch` result published directly | plus `disclosure_of_failure` guard | Keeps provably false MISMATCH receipts off the wall. |

---

## Test artifacts on the backend

These exist only as plumbing checks. They are **not** catches and neither
appears on the Square (`published: false`):

- `witness-preflight` — the receipt from the brief's own pre-flight check. Its
  signature field is the literal string `"test"`, so `/r/preflight` shows
  INVALID by construction. Safe to delete.
- `witness-signature-roundtrip-test` — receipt `a3634ab698f4c91f`, created to
  prove that a `generate_receipt()` signature survives a real backend
  round-trip and verifies in the browser. It does. Safe to delete.

## License

MIT
