# SEKS Changelog

Changes specific to the SEKS (Secure Execution Key Sequestration) fork of nushell.

For upstream nushell changes, see the [nushell releases](https://github.com/nushell/nushell/releases).

---

## [0.110.3-seks] - 2026-02-09

### Fixed
- **CI:** Add `contents: write` permission to release workflow. Fixes 403 error when publishing release artifacts.

---

## [0.110.2-seks] - 2026-02-09

### Fixed
- **seksh-git:** Use `x-access-token` as username for `--token` auth. Previously echoed the token for both username and password prompts, causing GitHub auth failures.

---

## [0.110.1-seks] - 2026-02-08

### Added
- **INTEGRATION.md:** Contract document for seksh ↔ seks-broker integration
- **broker.rs HTTP client:** Switched from Unix socket to HTTP REST API
  - Reads `SEKS_BROKER_URL` (default: `http://localhost:8787`)
  - Reads `SEKS_AGENT_TOKEN` for bearer auth
  - Uses `ureq` for HTTP requests

### Commands
- `getseks` — Fetch secret from broker, register for scrubbing (deprecated, use wrapped commands)
- `listseks` — List available secret names
- `seksh-http` — HTTP requests with internal credential injection
- `seksh-git` — Git operations with internal credential injection

### Security
- Output scrubbing with base64/hex encoding detection
- Secrets never enter shell memory when using wrapped commands

---

## Base Version

SEKS is forked from **nushell 0.110.1**. See [nushell 0.110.1 release notes](https://github.com/nushell/nushell/releases/tag/0.110.1) for base features.

---

## Versioning

SEKS releases use the format `<nushell-version>-seks` (e.g., `0.110.2-seks`).

- Major/minor tracks upstream nushell
- Patch increments for SEKS-specific fixes
- `-seks` suffix distinguishes from upstream
