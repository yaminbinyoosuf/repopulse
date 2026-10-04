"""Configuration for RepoPulse Sentinel.

Environment variables only. No shared servers, no coupling to any other project.

Two deliberate design points:

1. ``COGEXT_API_BASE`` is set here, at import time, *before* anything imports
   ``cogext_observe``. The package's ``session`` module reads
   ``COGEXT_API_BASE`` at import time, so setting it later has no effect.

2. External ``.env`` files are read with ``dotenv_values`` through an explicit
   allowlist rather than ``load_dotenv``. A foreign ``.env`` may contain
   database URLs and service-role keys; none of those belong in this process's
   environment, and this way none of them ever enter it. The real environment
   always wins over any file.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from dotenv import dotenv_values

PROJECT_ROOT = Path(__file__).resolve().parent
LOG_DIR = PROJECT_ROOT / "logs"

DEFAULT_COGEXT_API_URL = "https://api.cogextai.com/api/v1"

# Only these keys may be imported from a .env file. Everything else in the file
# is ignored outright.
_ENV_ALLOWLIST = frozenset(
    {
        "GITHUB_TOKEN",
        "DEEPSEEK_API_KEY",
        "OPENAI_API_KEY",
        "GROQ_API_KEY",
        "REPOPULSE_LLM_MODEL",
        "COGEXT_API_URL",
        "COGEXT_RECEIPT_KEY",
        "COGEXT_OBSERVE_LOCAL",
    }
)

# Default model per provider. These were checked against the live APIs rather
# than assumed; in particular a Groq model name inherited from another project
# was verified to return 404 model_not_found on that key.
PROVIDER_DEFAULTS = {
    "deepseek": ("https://api.deepseek.com/v1", "deepseek-chat"),
    "openai": ("https://api.openai.com/v1", "gpt-4o-mini"),
    "groq": ("https://api.groq.com/openai/v1", "openai/gpt-oss-120b"),
}

# Provider preference order when several keys are present. DeepSeek is the
# active provider. Groq is kept last as a dead fallback: it is only reached if
# neither DEEPSEEK_API_KEY nor OPENAI_API_KEY is set, so the code path survives
# without being used.
_PROVIDER_KEYS = (
    ("deepseek", "DEEPSEEK_API_KEY"),
    ("openai", "OPENAI_API_KEY"),
    ("groq", "GROQ_API_KEY"),
)

# Cycle behaviour
def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(str(os.environ.get(name, "")).strip())
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


MAX_REPOS = 5  # repositories actually audited per cycle
# The query given in the brief (language:python stars:>100, sorted by updated)
# returns mostly data and scraper repositories whose root carries neither
# requirements.txt nor pyproject.toml -- measured at 1 of 5 candidates on one
# cycle and 0 of 5 on the next, i.e. cycles that audit nothing at all.
# Considering more candidates is what makes the audit audit something; the
# search query itself is unchanged.
MAX_CANDIDATES = _env_int("REPOPULSE_CANDIDATES", 12, MAX_REPOS, 50)
MAX_DEPS_PER_REPO = 3
MAX_CATCHES_PER_CYCLE = 3
SLEEP_BETWEEN_REQUESTS = 1.5
CIRCUIT_BREAKER_THRESHOLD = 3
HTTP_TIMEOUT = 10.0
LLM_TIMEOUT = 90.0
LLM_MAX_TOKENS = 1200
MAX_RECEIPT_BYTES = 64 * 1024

_ENV_SOURCES: list[str] = []


def _load_env_files() -> None:
    """Pull only allowlisted keys out of .env files. Real env always wins."""
    candidates = [PROJECT_ROOT / ".env"]
    extra = os.environ.get("REPOPULSE_ENV_FILE")
    if extra:
        candidates.append(Path(extra).expanduser())

    for path in candidates:
        if not path.is_file():
            continue
        try:
            values = dotenv_values(path)
        except Exception:  # unreadable or malformed file: never fatal
            continue
        applied = [
            key
            for key, value in values.items()
            if value is not None and key in _ENV_ALLOWLIST and key not in os.environ
        ]
        for key in applied:
            os.environ[key] = str(values[key])
        if applied:
            # Record the count, never the values.
            _ENV_SOURCES.append(f"{path} ({len(applied)} allowlisted keys)")


_load_env_files()


def _detect_llm() -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    for provider, env_name in _PROVIDER_KEYS:
        key = os.environ.get(env_name)
        if key and key.strip():
            base_url, default_model = PROVIDER_DEFAULTS[provider]
            model = os.environ.get("REPOPULSE_LLM_MODEL") or default_model
            return provider, key.strip(), base_url, model
    return None, None, None, None


_LLM_PROVIDER, _LLM_KEY, _LLM_BASE_URL, _LLM_MODEL = _detect_llm()

COGEXT_API_URL = os.environ.get("COGEXT_API_URL", DEFAULT_COGEXT_API_URL).rstrip("/")

# Must happen before cogext_observe is imported anywhere.
os.environ.setdefault("COGEXT_API_BASE", COGEXT_API_URL)


@dataclass(frozen=True)
class Settings:
    cogext_api_url: str
    github_token: Optional[str]
    llm_provider: Optional[str]
    llm_key: Optional[str]
    llm_base_url: Optional[str]
    llm_model: Optional[str]
    receipt_key_is_default: bool
    observe_local: bool

    @property
    def has_llm(self) -> bool:
        return bool(self.llm_provider and self.llm_key)

    def describe(self) -> dict:
        """Non-secret view of the configuration, safe to log."""
        return {
            "cogext_api_url": self.cogext_api_url,
            "env_sources": _ENV_SOURCES or ["(none; using process environment)"],
            "github_token": "present" if self.github_token else "absent (unauthenticated, 60 req/h)",
            "llm_provider": self.llm_provider or "NONE",
            "llm_model": self.llm_model,
            "llm_key": "present (hidden)" if self.llm_key else "absent",
            "receipt_signing_key": (
                "package default" if self.receipt_key_is_default else "COGEXT_RECEIPT_KEY override"
            ),
            "observe_local": self.observe_local,
        }


settings = Settings(
    cogext_api_url=COGEXT_API_URL,
    github_token=os.environ.get("GITHUB_TOKEN") or None,
    llm_provider=_LLM_PROVIDER,
    llm_key=_LLM_KEY,
    llm_base_url=_LLM_BASE_URL,
    llm_model=_LLM_MODEL,
    receipt_key_is_default=not os.environ.get("COGEXT_RECEIPT_KEY"),
    observe_local=os.environ.get("COGEXT_OBSERVE_LOCAL") == "1",
)
