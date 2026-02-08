# seksh — Credential-Isolating Shell for AI Agents

[![Built on Nushell](https://img.shields.io/badge/built%20on-nushell-4E9A06.svg)](https://www.nushell.sh/)

**seksh** (Secure Execution Kernel for Shells) is a [nushell](https://github.com/nushell/nushell) fork designed to let AI agents use shell commands requiring authentication **without exposing credentials to the agent**.

## The Problem

AI agents need credentials to do useful work (API keys, tokens, passwords). But giving an agent raw access to secrets is dangerous — they can be:
- Leaked in output
- Exfiltrated via curl/wget
- Stored in logs or memory
- Extracted through prompt injection

## The Solution

Like SQL prepared statements separate query structure from data, seksh separates **command structure from secrets**.

```nu
# Agent writes this:
seksh-http get "https://api.github.com/user" --secret-header "Authorization: Bearer github_token"

# Broker injects the real token, executes the request
# Agent sees the response, but never the token value
```

Secrets are:
- Stored in a remote broker (not the shell)
- Injected at execution time (agent never sees them)
- Scrubbed from all output (defense in depth)

## Quick Start

```bash
# Clone and build
git clone https://github.com/SEKSBot/seksh.git
cd seksh && git checkout seks-shell
cargo build --release

# Configure broker (in ~/Library/Application Support/nushell/env.nu)
$env.SEKS_BROKER_URL = "https://your-broker.example.com"
$env.SEKS_AGENT_TOKEN = "seks_agent_..."

# Run
./target/release/nu
```

See [docs/INSTALL.md](docs/INSTALL.md) for detailed setup.

## Key Features

### Wrapped Commands
Credential-aware replacements for common tools:

| Command | Purpose |
|---------|---------|
| `seksh-http` | HTTP requests with secret injection |
| `seksh-git` | Git operations with token/SSH key injection |

See [docs/WRAPPED_COMMANDS.md](docs/WRAPPED_COMMANDS.md) for usage.

### Secret Commands

```nu
# List available secrets (names only, no values)
listseks

# Fetch a secret (for use in pipelines — output is scrubbed)
getseks 'api_key'
```

### Output Scrubbing

Any secret that *does* make it to output is automatically replaced:
- Literal matches → `<secret:name>`
- Base64 encoded → `<secret:name>`  
- Hex encoded → `<secret:name>`

## Architecture

```
┌─────────────────────────────────────┐
│            AI AGENT                 │
│  (never sees secret values)         │
└─────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│             SEKSH                   │
│  • Wrapped commands (seksh-http)    │
│  • Output scrubbing                 │
│  • getseks / listseks               │
└─────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│            BROKER                   │
│  (holds secrets, injects them)      │
│  • REST API with token auth         │
│  • Encrypted at rest                │
│  • Audit logging                    │
└─────────────────────────────────────┘
```

See [docs/SEKS_DESIGN.md](docs/SEKS_DESIGN.md) for full architecture.

## Documentation

- [INSTALL.md](docs/INSTALL.md) — Installation and setup
- [SEKS_DESIGN.md](docs/SEKS_DESIGN.md) — Architecture and design
- [WRAPPED_COMMANDS.md](docs/WRAPPED_COMMANDS.md) — seksh-http, seksh-git usage
- [SOCIAL_ENGINEERING_REDTEAM.md](docs/SOCIAL_ENGINEERING_REDTEAM.md) — Security analysis

## Relationship to Nushell

seksh is a hard fork of [nushell](https://github.com/nushell/nushell). We track upstream for bug fixes but diverge on security features. All nushell functionality works in seksh.

## License

MIT — same as nushell.

---

*Part of the [SEKSBot](https://github.com/SEKSBot) project — secure infrastructure for AI agents.*
