"""Vaultwarden / Bitwarden Password Manager (``bw`` CLI) secret source.

Hermes pulls API keys from a Vaultwarden (or Bitwarden) vault item at
process startup.  Vaultwarden implements the Bitwarden Password Manager
API — not Bitwarden Secrets Manager — so the ``bws`` CLI used by the
bundled ``secrets.bitwarden`` source does not work with it.  This plugin
bridges that gap.

Design summary
--------------

* ``bw`` is NOT auto-installed.  Install it from your package manager or
  https://github.com/bitwarden/clients/releases.  Resolution order:
  ``secrets.vaultwarden.binary_path`` (pinned) → ``<hermes_home>/bin/bw``
  → ``PATH``.
* The session token is stored in ``~/.hermes/.env`` as ``BW_SESSION``
  (or the name chosen in ``secrets.vaultwarden.session_env``).  Obtain it
  with ``export BW_SESSION=$(bw unlock --raw)`` after logging in.
* Secrets come from a single named vault item::

      bw get item -- "<item_name>"     (BW_SESSION passed via child env)

  Setup records the discovered custom-field names in ``allowed_env_vars``.
  Later custom fields are skipped until explicitly allowed, and high-risk
  process/network control variables are always blocked.  The item's
  structural ``login.username``, ``login.password`` and ``notes`` are only
  exported when the user opts in via ``username_env`` / ``password_env`` /
  ``notes_env``.  :meth:`VaultwardenSource.fetch` never writes
  ``os.environ`` itself.
* Caching: off by default.  This is a breaking safety default for configs
  that omit ``cache_ttl_seconds``: no cache is read or written unless the
  value is positive.  When positive, a two-layer cache is used (in-process
  dict + disk JSON via the shared
  :class:`agent.secret_sources._cache.DiskCache` substrate), written to
  ``<hermes_home>/cache/vaultwarden_cache.json``.
* Failures NEVER block Hermes startup — ``fetch()`` returns a
  :class:`FetchResult` with ``error``/``error_kind`` set.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from agent.secret_sources.base import (
    ErrorKind,
    FetchResult,
    SecretSource,
    is_valid_env_name,
    run_secret_cli,
    scrub_ansi,
)
from agent.secret_sources._cache import CachedFetch, DiskCache, resolve_cache_home

logger = logging.getLogger(__name__)

_BW_RUN_TIMEOUT = 30.0
_DEFAULT_SESSION_ENV = "BW_SESSION"
_DEFAULT_CACHE_TTL = 0.0

# Extra env vars the bw child process may need beyond run_secret_cli's
# base allowlist (HOME/PATH/locale).  BITWARDENCLI_APPDATA_DIR relocates
# bw's data directory; without it a user with a custom location would
# silently talk to an empty vault.
_BW_ALLOW_ENV = ("BITWARDENCLI_APPDATA_DIR",)

_BLOCKED_ENV_EXACT = {
    "ALL_PROXY",
    "ANTHROPIC_BASE_URL",
    "AWS_CONFIG_FILE",
    "AWS_ENDPOINT_URL",
    "AWS_PROFILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "BASH_ENV",
    "BITWARDENCLI_APPDATA_DIR",
    "CDPATH",
    "CLOUDSDK_CONFIG",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "ENV",
    "GIT_ASKPASS",
    "GIT_CONFIG_GLOBAL",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "IFS",
    "KUBECONFIG",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "NODE_OPTIONS",
    "NO_PROXY",
    "OLLAMA_HOST",
    "OPENAI_API_BASE",
    "OPENAI_BASE_URL",
    "OPENROUTER_BASE_URL",
    "PATH",
    "PROMPT_COMMAND",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "REQUESTS_CA_BUNDLE",
    "RUBYOPT",
    "SHELLOPTS",
    "SSL_CERT_FILE",
}
# These broad suffixes block common exfiltration pivots: LLM endpoint
# redirection, traffic interception through proxies, and TLS trust overrides.
_BLOCKED_ENV_SUFFIXES = (
    "_BASE_URL",
    "_PROXY",
    "_CA_BUNDLE",
)

_CacheKey = Tuple[str, str, str, str, str, str, str]
# (resolved_home, session_fingerprint, item_name,
#  username_env, password_env, notes_env, allowed_env_key)


def _cache_key_str(cache_key: _CacheKey) -> str:
    (
        _home,
        session_fp,
        item_name,
        username_env,
        password_env,
        notes_env,
        allowed_env_key,
    ) = cache_key
    return (
        f"vw|{session_fp}|{item_name}|{username_env}|{password_env}|"
        f"{notes_env}|{allowed_env_key}"
    )


_CACHE: Dict[_CacheKey, CachedFetch] = {}
_DISK_CACHE: DiskCache[_CacheKey] = DiskCache(
    "vaultwarden_cache.json", key_serializer=_cache_key_str
)


def _disk_cache_path(home_path: Optional[Path] = None) -> Path:
    return _DISK_CACHE.path(home_path)


# ---------------------------------------------------------------------------
# Binary discovery
# ---------------------------------------------------------------------------


def _hermes_bin_dir() -> Path:
    from hermes_constants import get_hermes_home

    return get_hermes_home() / "bin"


def find_bw(pinned: Optional[str] = None) -> Optional[Path]:
    """Return a path to a usable ``bw`` binary, or None.

    Resolution order:
      1. ``pinned`` (``secrets.vaultwarden.binary_path``) — when set it is
         authoritative: a broken pin returns None rather than silently
         falling back to a different binary.
      2. ``<hermes_home>/bin/bw``
      3. ``shutil.which("bw")`` (system PATH)

    ``bw`` is not auto-installed — users install it themselves.
    """
    if pinned and str(pinned).strip():
        p = Path(str(pinned)).expanduser()
        if p.exists() and os.access(p, os.X_OK):
            return p
        return None
    try:
        managed = _hermes_bin_dir() / ("bw.exe" if os.name == "nt" else "bw")
        if managed.exists() and os.access(managed, os.X_OK):
            return managed
    except Exception:  # noqa: BLE001 — host helper unavailable in bare tests
        pass
    system = shutil.which("bw")
    return Path(system) if system else None


# ---------------------------------------------------------------------------
# Secret fetch
# ---------------------------------------------------------------------------


def _session_fingerprint(session: str) -> str:
    return hashlib.sha256(session.encode("utf-8")).hexdigest()[:16]


def _is_blocked_env_name(name: str) -> bool:
    upper = name.upper()
    return upper in _BLOCKED_ENV_EXACT or any(
        upper.endswith(suffix) for suffix in _BLOCKED_ENV_SUFFIXES
    )


def normalize_allowed_env_vars(raw: object) -> Tuple[Optional[Set[str]], List[str]]:
    """Normalize the custom-field export allowlist.

    Returns:
      * ``None`` for unset legacy mode, which allows all non-blocked fields.
      * an empty set for an explicit empty list/string, which denies all fields.
      * a populated set for an explicit allowlist.

    Invalid names are skipped with warnings.  Invalid value types fail closed by
    returning an empty set plus a warning.
    """
    if raw is None:
        return None, [
            "secrets.vaultwarden.allowed_env_vars is unset; legacy mode allows "
            "all non-blocked custom fields"
        ]
    if isinstance(raw, str):
        values: Iterable[object] = [
            part.strip() for part in raw.replace("\n", ",").split(",")
        ]
    elif isinstance(raw, (list, tuple, set, frozenset)):
        values = raw
    else:
        return set(), [
            "secrets.vaultwarden.allowed_env_vars must be a list or comma-separated string"
        ]

    allowed: Set[str] = set()
    warnings: List[str] = []
    for value in values:
        name = str(value or "").strip()
        if not name:
            continue
        if not is_valid_env_name(name):
            warnings.append(
                f"Skipping allowed_env_vars entry {name!r}: not a valid env-var name"
            )
            continue
        allowed.add(name)
    return allowed, warnings


def _allowed_env_key(allowed_env_vars: Optional[Set[str]]) -> str:
    if allowed_env_vars is None:
        return "*"
    return ",".join(sorted(allowed_env_vars))


def fetch_vaultwarden_secrets(
    *,
    session: str,
    item_name: str,
    binary: Optional[Path] = None,
    cache_ttl_seconds: float = _DEFAULT_CACHE_TTL,
    use_cache: bool = True,
    home_path: Optional[Path] = None,
    username_env: Optional[str] = None,
    password_env: Optional[str] = None,
    notes_env: Optional[str] = None,
    allowed_env_vars: Optional[Iterable[str]] = None,
    discovered_env_vars: Optional[List[str]] = None,
) -> Tuple[Dict[str, str], List[str]]:
    """Pull secrets from a vault item via ``bw get item``.

    Allowed custom fields become env vars.  ``login.username``,
    ``login.password`` and ``notes`` are structural (not custom fields)
    and are only included when the caller opts in via ``username_env`` /
    ``password_env`` / ``notes_env`` — the target env-var name for each.

    Returns ``(secrets_dict, warnings_list)``.

    Raises :class:`RuntimeError` for fatal conditions (missing binary,
    auth failure, unknown item, unparseable output).
    """
    if not session:
        raise RuntimeError("Vaultwarden session token is empty")
    if not item_name:
        raise RuntimeError("Vaultwarden item_name is empty")

    allowed_set, allowed_warnings = normalize_allowed_env_vars(allowed_env_vars)
    runtime_warnings: List[str] = []
    if use_cache and cache_ttl_seconds <= 0:
        runtime_warnings.append(
            "Vaultwarden cache disabled because cache_ttl_seconds is not positive"
        )

    cache_key: _CacheKey = (
        str(resolve_cache_home(home_path)),
        _session_fingerprint(session),
        item_name,
        username_env or "",
        password_env or "",
        notes_env or "",
        _allowed_env_key(allowed_set),
    )
    caching_enabled = use_cache and cache_ttl_seconds > 0
    if caching_enabled:
        cached = _CACHE.get(cache_key)
        if cached and cached.is_fresh(cache_ttl_seconds):
            return cached.secrets, [*allowed_warnings, *runtime_warnings]
        disk_cached = _DISK_CACHE.read(cache_key, cache_ttl_seconds, home_path)
        if disk_cached is not None:
            _CACHE[cache_key] = disk_cached
            return disk_cached.secrets, [*allowed_warnings, *runtime_warnings]

    bw = binary or find_bw()
    if bw is None:
        raise RuntimeError(
            "bw binary not found.  Install it from your package manager or "
            "https://github.com/bitwarden/clients/releases"
        )

    secrets, warnings = _run_bw_get_item(
        bw,
        session,
        item_name,
        username_env=username_env,
        password_env=password_env,
        notes_env=notes_env,
        allowed_env_vars=allowed_set,
        discovered_env_vars=discovered_env_vars,
    )
    all_warnings = [*allowed_warnings, *runtime_warnings, *warnings]
    import time as _time

    entry = CachedFetch(secrets=secrets, fetched_at=_time.time())
    if caching_enabled:
        _CACHE[cache_key] = entry
        _DISK_CACHE.write(cache_key, entry, cache_ttl_seconds, home_path)
    return secrets, all_warnings


def _load_bw_item(bw: Path, session: str, item_name: str) -> Any:
    """Load one vault item as JSON; return None for empty output.

    Raises RuntimeError when ``bw`` fails or returns non-JSON output.
    """
    # Session travels via the child env (bw reads BW_SESSION natively)
    # instead of a --session argv flag, keeping the token out of
    # /proc/<pid>/cmdline.  The item name follows a `--` terminator so a
    # user-named item like "--raw" can never parse as a flag.
    proc = run_secret_cli(
        [str(bw), "get", "item", "--", item_name],
        allow_env=_BW_ALLOW_ENV,
        extra_env={"BW_SESSION": session},
        timeout=_BW_RUN_TIMEOUT,
    )

    if proc.returncode != 0:
        err = scrub_ansi((proc.stderr or proc.stdout or "")).strip()
        raise RuntimeError(f"bw exited {proc.returncode}: {err[:200]}")

    raw = (proc.stdout or "").strip()
    if not raw:
        return None

    try:
        item = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"bw returned non-JSON output: {exc}") from exc
    return item


def _run_bw_get_item(
    bw: Path,
    session: str,
    item_name: str,
    *,
    username_env: Optional[str] = None,
    password_env: Optional[str] = None,
    notes_env: Optional[str] = None,
    allowed_env_vars: Optional[Set[str]] = None,
    discovered_env_vars: Optional[List[str]] = None,
) -> Tuple[Dict[str, str], List[str]]:
    item = _load_bw_item(bw, session, item_name)
    if item is None:
        return {}, ["bw returned no output"]

    if not isinstance(item, dict):
        raise RuntimeError(f"bw returned unexpected shape: {type(item).__name__}")

    fields = item.get("fields") or []
    if not isinstance(fields, list):
        fields = []

    secrets: Dict[str, str] = {}
    warnings: List[str] = []
    for f in fields:
        if not isinstance(f, dict):
            continue
        name = f.get("name")
        if not isinstance(name, str):
            continue
        if not is_valid_env_name(name):
            warnings.append(f"Skipping field {name!r}: not a valid env-var name")
            continue
        if _is_blocked_env_name(name):
            warnings.append(
                f"Skipping field {name!r}: env var is blocked for agent safety"
            )
            continue
        value = f.get("value")
        if value is None:
            continue
        value = str(value)
        if allowed_env_vars is not None and name not in allowed_env_vars:
            warnings.append(
                f"Skipping field {name!r}: not listed in allowed_env_vars"
            )
            continue
        if discovered_env_vars is not None:
            discovered_env_vars.append(name)
        secrets[name] = value

    if not fields and not (username_env or password_env or notes_env):
        return {}, [
            "item has no custom fields — add fields named after the env vars "
            "you want to export, or set username_env/password_env/notes_env "
            "to pull the login/notes values instead"
        ]

    login = item.get("login")
    login = login if isinstance(login, dict) else {}
    for env_name, value, label in (
        (username_env, login.get("username"), "login.username"),
        (password_env, login.get("password"), "login.password"),
        (notes_env, item.get("notes"), "notes"),
    ):
        if not env_name:
            continue
        if value is None or value == "":
            warnings.append(f"item has no {label} to export as {env_name}")
            continue
        if _is_blocked_env_name(env_name):
            warnings.append(
                f"Skipping {label} binding {env_name!r}: env var is blocked "
                "for agent safety"
            )
            continue
        if env_name in secrets:
            warnings.append(
                f"{env_name} set by both a custom field and {label} — "
                f"{label} wins"
            )
        secrets[env_name] = str(value)

    return secrets, warnings


# ---------------------------------------------------------------------------
# Error classification — maps RuntimeError text onto the ErrorKind taxonomy
# ---------------------------------------------------------------------------


def _classify_bw_error(message: str) -> ErrorKind:
    lowered = (message or "").lower()
    if "timed out" in lowered:
        return ErrorKind.TIMEOUT
    if "failed to invoke" in lowered or "binary not found" in lowered:
        return ErrorKind.BINARY_MISSING
    if any(tok in lowered for tok in (
        "session", "unlock", "not logged in", "vault is locked", "locked",
        "unauthorized", "invalid master password", "mac failed",
    )):
        return ErrorKind.AUTH_EXPIRED
    if "not found" in lowered or "more than one result" in lowered:
        return ErrorKind.REF_INVALID
    if any(tok in lowered for tok in (
        "network", "connection", "resolve host", "dns",
        "econnrefused", "enotfound", "etimedout",
    )):
        return ErrorKind.NETWORK
    return ErrorKind.INTERNAL


def resolve_login_bindings(
    cfg: dict,
) -> Tuple[Dict[str, Optional[str]], List[str]]:
    """Validate cfg's username_env/password_env/notes_env.

    Returns ``(bindings, warnings)``.  Empty/missing -> ``None`` (opt-out,
    the default).  Non-empty but not a valid env-var name -> ``None`` plus
    a warning — never raises; callers embed the warning into their own
    reporting.
    """
    bindings: Dict[str, Optional[str]] = {}
    warnings: List[str] = []
    for key in ("username_env", "password_env", "notes_env"):
        raw = str(cfg.get(key) or "").strip()
        if not raw:
            bindings[key] = None
        elif is_valid_env_name(raw):
            bindings[key] = raw
        else:
            bindings[key] = None
            warnings.append(
                f"secrets.vaultwarden.{key} {raw!r} is not a valid "
                "env-var name — ignoring it"
            )
    return bindings, warnings


# ---------------------------------------------------------------------------
# The SecretSource — registered via PluginContext.register_secret_source()
# ---------------------------------------------------------------------------


class VaultwardenSource(SecretSource):
    """Vaultwarden vault-item custom fields as env vars.

    A **bulk** source: the user names one vault item and every custom
    field of that item is offered implicitly — there is no per-var
    VAR→ref binding, so explicit mapped bindings (e.g. 1Password
    ``env:`` entries) rightly outrank it on contested vars.
    """

    name = "vaultwarden"
    label = "Vaultwarden"
    shape = "bulk"
    scheme = None

    def protected_env_vars(self, cfg: dict):
        session_env = _DEFAULT_SESSION_ENV
        if isinstance(cfg, dict):
            candidate = str(cfg.get("session_env") or session_env)
            if is_valid_env_name(candidate):
                session_env = candidate
        return frozenset({session_env})

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Master switch", "default": False},
            "session_env": {
                "description": "Env var holding the `bw unlock --raw` session token",
                "default": _DEFAULT_SESSION_ENV,
            },
            "item_name": {
                "description": "Vault item whose custom fields become env vars",
                "default": "",
            },
            "username_env": {
                "description": (
                    "Env var to export the item's login.username as.  "
                    "Empty (default) means don't export it."
                ),
                "default": "",
            },
            "password_env": {
                "description": (
                    "Env var to export the item's login.password as.  "
                    "Empty (default) means don't export it."
                ),
                "default": "",
            },
            "notes_env": {
                "description": (
                    "Env var to export the item's notes as.  "
                    "Empty (default) means don't export it."
                ),
                "default": "",
            },
            "override_existing": {
                "description": (
                    "Overwrite env vars already set by .env / the shell.  "
                    "Defaults to False (bundled sources default True) — "
                    "preserves the historical in-tree behaviour."
                ),
                "default": False,
            },
            "allowed_env_vars": {
                "description": (
                    "Custom-field env vars allowed to export.  If unset, legacy "
                    "configs allow all non-blocked fields; an empty list denies "
                    "all custom fields; setup writes an explicit list."
                ),
                "default": None,
            },
            "cache_ttl_seconds": {
                "description": "Cache TTL for both cache layers; 0 disables caching",
                "default": int(_DEFAULT_CACHE_TTL),
            },
            "binary_path": {
                "description": "Pin an exact bw binary path (skips PATH lookup)",
                "default": "",
            },
        }

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        result = FetchResult()
        cfg = cfg if isinstance(cfg, dict) else {}

        session_env = str(cfg.get("session_env") or _DEFAULT_SESSION_ENV)
        session = os.environ.get(session_env, "").strip()
        if not session:
            result.error = (
                f"secrets.vaultwarden.enabled is true but {session_env} is not "
                "set.  Run `bw unlock --raw` and store the output in your .env "
                f"file as {session_env}=<token>, or run "
                "`hermes vaultwarden setup`."
            )
            result.error_kind = ErrorKind.NOT_CONFIGURED
            return result

        item_name = str(cfg.get("item_name") or "").strip()
        if not item_name:
            result.error = (
                "secrets.vaultwarden.item_name is empty.  "
                "Run `hermes vaultwarden setup`."
            )
            result.error_kind = ErrorKind.NOT_CONFIGURED
            return result

        binary = find_bw(cfg.get("binary_path"))
        result.binary_path = binary
        if binary is None:
            result.error = (
                "bw binary not found.  Install it from your package manager or "
                "https://github.com/bitwarden/clients/releases"
            )
            result.error_kind = ErrorKind.BINARY_MISSING
            return result

        try:
            ttl = float(cfg.get("cache_ttl_seconds", _DEFAULT_CACHE_TTL))
        except (TypeError, ValueError):
            ttl = _DEFAULT_CACHE_TTL

        login_bindings, binding_warnings = resolve_login_bindings(cfg)
        allowed_env_vars, allowed_warnings = normalize_allowed_env_vars(
            cfg.get("allowed_env_vars")
        )
        result.warnings.extend(binding_warnings + allowed_warnings)

        try:
            secrets, warnings = fetch_vaultwarden_secrets(
                session=session,
                item_name=item_name,
                binary=binary,
                cache_ttl_seconds=ttl,
                home_path=home_path,
                username_env=login_bindings["username_env"],
                password_env=login_bindings["password_env"],
                notes_env=login_bindings["notes_env"],
                allowed_env_vars=allowed_env_vars,
            )
        except RuntimeError as exc:
            result.error = str(exc)
            result.error_kind = _classify_bw_error(str(exc))
            return result
        except Exception as exc:  # noqa: BLE001 — contract: never raise
            result.error = f"unexpected error: {exc}"
            result.error_kind = ErrorKind.INTERNAL
            return result

        result.secrets = secrets
        result.warnings.extend(warnings)
        return result


# ---------------------------------------------------------------------------
# Test hook
# ---------------------------------------------------------------------------


def _reset_cache_for_tests(home_path: Optional[Path] = None) -> None:
    _CACHE.clear()
    _DISK_CACHE.clear(home_path)
