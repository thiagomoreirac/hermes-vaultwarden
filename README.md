# hermes-vaultwarden

Hermes Agent plugin: pull env vars from a **Vaultwarden** (or Bitwarden
Password Manager) vault item's custom fields at process startup, via the
`bw` CLI.

Vaultwarden implements the Bitwarden *Password Manager* API — not
*Secrets Manager* — so Hermes' bundled `secrets.bitwarden` source (which
uses the `bws` CLI) does not work with self-hosted Vaultwarden
instances.  This plugin bridges that gap as an external
[`SecretSource`](https://github.com/NousResearch/hermes-agent) plugin
(successor to in-tree PR
[#42300](https://github.com/NousResearch/hermes-agent/pull/42300),
reworked for the pluggable interface introduced in
[#59498](https://github.com/NousResearch/hermes-agent/pull/59498)).

## Install

```bash
git clone https://github.com/hansipie/hermes-vaultwarden ~/Code/hermes-vaultwarden
ln -s ~/Code/hermes-vaultwarden ~/.hermes/plugins/vaultwarden
```

User plugins are **opt-in** — add the plugin to `plugins.enabled` in
`~/.hermes/config.yaml` (the setup wizard does this for you):

```yaml
plugins:
  enabled:
    - vaultwarden
```

Install the `bw` CLI (not auto-installed): `npm install -g @bitwarden/cli`,
snap, or the native binary from https://bitwarden.com/help/cli/.

## Setup

```bash
bw config server https://your-vaultwarden.example.com
bw login
export BW_SESSION=$(bw unlock --raw)
hermes vaultwarden setup
```

The wizard verifies `bw`, stores the session token in `~/.hermes/.env`,
lets you pick the vault item, optionally maps `login.username` /
`login.password` / `notes` to env vars, records an explicit allowlist of
exportable custom fields, test-fetches it, and enables everything.

Secrets are read from **one vault item's custom fields** — name each
field after the env var it should set (e.g. `OPENROUTER_API_KEY`).
The item's structural `login.username` / `login.password` / `notes`
are not custom fields and are ignored unless you opt in — either
answer the wizard's prompts (blank = skip) or pass
`--username-env` / `--password-env` / `--notes-env` for non-interactive
runs (see Config below). Re-running `setup` and leaving a binding blank
clears it from `config.yaml`.

## Commands

| Command | What it does |
|---|---|
| `hermes vaultwarden setup` | Interactive wizard (flags: `--session-stdin`, `--item-name`, `--server-url`, `--username-env`, `--password-env`, `--notes-env`, `--allow-env`, `--override-existing` for non-TTY) |
| `hermes vaultwarden status` | Config, binary, server, session presence |
| `hermes vaultwarden sync` | `bw sync` + fresh fetch, dry-run table; `--apply` exports into the current process |
| `hermes vaultwarden disable` | Flips `secrets.vaultwarden.enabled` to false and clears the disk cache |

## Config (`secrets.vaultwarden.*` in config.yaml)

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Master switch |
| `session_env` | `BW_SESSION` | Env var holding the `bw unlock --raw` token |
| `item_name` | — | Vault item whose custom fields become env vars |
| `username_env` | — | Env var for `login.username`; unset = not exported |
| `password_env` | — | Env var for `login.password`; unset = not exported |
| `notes_env` | — | Env var for the item's `notes`; unset = not exported |
| `allowed_env_vars` | unset | Custom-field env vars allowed to export; unset = legacy all non-blocked, `[]` = deny all |
| `override_existing` | `false` | Overwrite vars already set by `.env`/shell (never another secret source) |
| `cache_ttl_seconds` | `0` | TTL for both cache layers; `0` disables caching entirely |
| `binary_path` | — | Pin an exact `bw` binary path |
| `timeout_seconds` | `120` | Orchestrator wall-clock budget around the fetch |

Config keys are identical to the old in-tree PR #42300 branch — an
existing config keeps working unchanged.

## Behaviour & caveats

- **Bulk source**: custom fields are offered only when allowlisted.
  New setup runs record the discovered fields in `allowed_env_vars`; later
  fields added to the vault item are skipped until you explicitly allow
  them. Existing configs without `allowed_env_vars` keep legacy behaviour
  for non-blocked names.
- **Blocked env vars**: process-control and network-routing names such as
  `PATH`, `PYTHONPATH`, `LD_PRELOAD`, proxy variables, `OPENAI_BASE_URL`,
  `ANTHROPIC_BASE_URL`, `OPENROUTER_BASE_URL`, `KUBECONFIG`, and cloud
  credential-file selectors are never exported, even if allowlisted.
  Explicit mapped bindings (e.g. 1Password `env:` entries) outrank
  Vaultwarden on contested vars; conflicts are warned, never silently
  clobbered.
- **Login/notes bindings**: `username_env`/`password_env`/`notes_env`
  are opt-in — there's no default name to guess a structural field
  into, so unset means not exported. If a binding's target name also
  matches a custom field, the login/notes value wins and a warning is
  emitted.
- The session token env var is **protected** — a vault field named
  `BW_SESSION` can never overwrite the credential used to reach the vault.
- **Timing**: plugin secret sources are discovered *after* the very
  first env load of the process that discovers them.  They apply to every
  Hermes process spawned afterwards (gateway children, cron sessions,
  subagents).  For secrets the first interactive process itself needs,
  use `hermes vaultwarden sync --apply` or keep them in `.env`.
- Failures (missing binary, expired session, unknown item) never block
  startup — they surface as one-line warnings with a machine-readable
  error kind.
- Cache: in-process dict + `~/.hermes/cache/vaultwarden_cache.json`
  (atomic writes, mode `0600`, keyed on a session fingerprint — the
  token itself is never written).  The default TTL is `0` for highest
  sensitivity; set a positive TTL only if you accept short-lived secret
  material on disk.  A stale `bw_cache.json` from the old in-tree branch
  is dead weight and safe to delete.
- **Session input**: avoid passing live `BW_SESSION` values on a command
  line. For non-interactive setup, either export the session in the
  environment or pipe it with `bw unlock --raw | hermes vaultwarden setup
  --session-stdin --item-name Hermes`.
- **Binary trust**: safest operation pins `secrets.vaultwarden.binary_path`
  to a trusted `bw` executable. If the pin is broken the plugin fails
  closed instead of falling back to `PATH`; unpinned `PATH` lookup is
  convenience mode.

## Hermes agent safety

For agent use, treat the Vaultwarden item as part of your trusted computing
base. A malicious or accidental extra field could otherwise influence child
processes. Recommended config:

- Keep `allowed_env_vars` narrow and review it when adding new secrets.
- Keep `override_existing: false` unless a specific variable must be
  replaced.
- Keep `cache_ttl_seconds: 0` for highly sensitive agent credentials.
- Pin `binary_path` to a trusted `bw` binary.
- Do not store routing variables, proxy variables, shell loader variables,
  or cloud credential-file selectors in the Vaultwarden item.

## Tests

```bash
HERMES_AGENT_SRC=~/Code/hermes-agent \
  uv run --with pytest --with rich --with pyyaml pytest tests/ -v
```

`HERMES_AGENT_SRC` must point at a hermes-agent checkout that includes
the `SecretSource` interface (post-#59498).  The suite is hermetic (no
real vault, subprocess mocked) and includes the upstream
`SecretSourceConformance` kit.
