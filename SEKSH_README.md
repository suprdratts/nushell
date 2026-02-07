# seksh — Credential-Isolating Shell for AI Agents

A nushell fork that allows AI agents to use credentials without exposing them to shell memory.

Like SQL prepared statements separate query structure from data, seksh separates commands from secrets.

## The Problem

AI agents need credentials (API keys, tokens, passwords) to do useful work. But if secrets enter shell memory, they can leak through:
- Command history
- Process memory dumps
- Output scraping
- Social engineering

## The Solution

Secrets **never enter the shell**. They go directly from the broker to wrapped commands:

```
Broker → seksh-http → External API
       ↘ seksh-git → Git remote
       
Shell sees: Command structure + "[REDACTED]"
Shell never sees: Actual credential values
```

## Quick Start

### Prerequisites
- Rust toolchain
- Agent token from seks-broker

### Build
```bash
git clone https://github.com/SEKSBot/seksh.git
cd seksh
git checkout seks-shell
cargo build --release
```

### Configure
```bash
export SEKS_BROKER_URL="https://seks-broker.stcredzero.workers.dev"
export SEKS_AGENT_TOKEN="seks_agent_<your_token>"
```

### Use
```bash
# List available secrets
./target/release/nu -c 'listseks'

# HTTP with injected bearer token
./target/release/nu -c 'seksh-http GET "https://api.github.com/user" --auth-bearer GITHUB_TOKEN'

# Git push with token auth
./target/release/nu -c 'seksh-git push origin main --token GITHUB_TOKEN'
```

## Commands

| Command | Purpose |
|---------|---------|
| `listseks` | List secrets available from broker |
| `seksh-http` | HTTP requests with credential injection |
| `seksh-git` | Git operations with credential injection |

## Architecture

```
┌─────────────────────┐     ┌──────────────┐     ┌─────────────────┐
│   seksbot Agent     │────▶│  seks-broker │────▶│  External APIs  │
│   (seksh shell)     │     │  (CF Worker) │     │  (GitHub, etc.) │
└─────────────────────┘     └──────────────┘     └─────────────────┘
         │                         │
         │ Command structure       │ Injects real credentials
         │ (no secrets)            │ (never seen by shell)
         ▼                         ▼
    Shell memory              HTTPS request
    is CLEAN                  has AUTH
```

## Related

- [seks-broker](https://github.com/SEKSBot/seks-broker) — Credential broker (Cloudflare Workers)
- [nushell](https://github.com/nushell/nushell) — Upstream shell (we're a fork)

## Security Model

Defense-in-depth, not Fort Knox:
- Secrets never enter shell memory
- Output is scrubbed for accidental leaks
- Broker controls which agents access which secrets
- Audit logging of all secret access

## License

MIT (inherited from nushell)
