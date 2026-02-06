# SEKS Shell Design Document

**Secure Execution Kernel for Shells**  
*Draft v0.1 — February 2026*

---

## Overview

SEKS Shell (seksh) is a fork of [nushell](https://github.com/nushell/nushell) designed to allow AI agents to use shell commands that require authentication **without exposing credentials to the agent**.

The core insight: like SQL prepared statements separate query structure from data, SEKS separates command structure from secrets.

---

## Design Principles

1. **Agents never see secret values** — only `<secret:name>` placeholders
2. **Correct usage is easier than incorrect usage** — self-reinforcing security
3. **Defense in depth** — multiple layers, none needs to be perfect
4. **Pragmatic, not paranoid** — we're raising the bar, not building Fort Knox

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        AGENT                                │
│  (writes shell commands, sees only scrubbed output)         │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                       SEKSH                                 │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ LAYER 1: Blessed Wrappers                           │   │
│  │   curl, git, aws, gh, http, fetch...                │   │
│  │   → Handle secrets correctly, just work             │   │
│  └─────────────────────────────────────────────────────┘   │
│                          │                                  │
│                          ▼                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ LAYER 2: getseks command                            │   │
│  │   → Fetches real value from broker                  │   │
│  │   → Registers value for scrubbing                   │   │
│  │   → Returns real value to command                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                          │                                  │
│                          ▼                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ LAYER 3: Output Scrubbing                           │   │
│  │   → Literal string match                            │   │
│  │   → Base64 encoded detection                        │   │
│  │   → Hex encoded detection                           │   │
│  │   → Replaces with <secret:name>                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                       BROKER                                │
│  (runs outside shell, provides secrets on request)          │
│                                                             │
│  - Holds secret registry (name → value)                     │
│  - Listens on Unix socket or localhost                      │
│  - Authenticates requests (shell must prove identity)       │
│  - Never exposes secrets to agent-visible surfaces          │
└─────────────────────────────────────────────────────────────┘
```

---

## How It Works

### Example: API Call

```nu
# Agent writes:
http get "https://api.github.com/user" --headers {
  Authorization: $"Bearer (getseks 'github_token')"
}
```

**Execution flow:**

1. Parser creates AST with `getseks` call
2. Evaluator executes `getseks "github_token"`:
   - Contacts broker via Unix socket
   - Broker returns real value: `"ghp_abc123..."`
   - `getseks` registers value in scrub registry
   - Returns real value to string interpolation
3. `http get` executes with real token, API call succeeds
4. Response flows through output scrubber
5. Any occurrence of `ghp_abc123...` → `<secret:github_token>`
6. Agent sees only scrubbed output

### Example: External Command

```nu
# Agent writes:
^curl -H $"Authorization: Bearer (getseks 'token')" https://api.example.com
```

**This works because:**
- `getseks` returns real value (curl gets what it needs)
- If curl echoes the token, scrubbing catches it
- Agent never sees the real value

---

## The `getseks` Command

```nu
# Syntax
getseks <secret-name>

# Returns
The actual secret value (for use in commands)

# Side effects
- Registers the value for output scrubbing
- Scrubbing persists for the shell session
```

**Implementation notes:**
- Built-in command in `nu-seks` crate
- Communicates with broker via Unix socket
- Caches secrets locally (one fetch per session)

---

## The Broker

The broker is a **separate service** (not embedded in seksh). We're using a 
**Cloudflare Workers implementation** for cloud-native deployment:

**Repository:** `~/seks-broker/` (TypeScript, Hono framework)

```
┌─────────────────────────────────────────────────────────────┐
│ SEKS BROKER (Cloudflare Workers)                            │
│                                                             │
│ - REST API with authentication                              │
│ - Secrets encrypted at rest (AES-GCM)                       │
│ - Multi-tenant (multiple agents, isolated secrets)          │
│ - Web admin UI for secret management                        │
│ - Audit logging                                             │
│                                                             │
│ Endpoints:                                                  │
│   POST /v1/secrets/get    → fetch a secret                  │
│   POST /v1/secrets/list   → list secret names               │
│   POST /v1/proxy/request  → proxy request w/ cred injection │
│                                                             │
│ Authentication:                                             │
│   Bearer token per agent (seks_agent_...)                   │
│                                                             │
│ Deployment:                                                 │
│   - Production: wrangler deploy                             │
│   - Local dev: wrangler dev (localhost:8787)                │
└─────────────────────────────────────────────────────────────┘
```

**Why Cloudflare Workers?**
- No dependency conflicts with seksh shell
- Cloud-native: runs anywhere, no server to manage
- Built-in encryption, D1 database, audit logging
- Local dev mode for offline/airgapped use

---

## Self-Reinforcing Security

The design is **self-correcting**:

| Agent Action | Result |
|--------------|--------|
| Uses blessed wrapper correctly | ✅ Just works |
| Uses `getseks` with external | ✅ Works, scrubbing protects |
| Tries to `echo (getseks x)` | Output scrubbed, sees `<secret:x>` |
| Tries to exfiltrate via curl | Token scrubbed from response |
| Hardcodes a secret | No scrubbing, but that's agent's own credential |

**The path of least resistance is correct usage.**

---

## What's NOT In Scope

We accept these limitations (whack-a-mole):

- **Timing attacks** — execution time could leak info
- **Single-char exfiltration** — leak one char at a time
- **Exotic encodings** — rot13, custom ciphers, etc.
- **Side channels** — DNS, file creation timing, etc.
- **Malicious blessed commands** — we trust our own code

These require much more sophisticated defenses and are out of scope for SEKS MVP.

---

## Implementation Checklist

### Phase 1: Foundation (DONE)
- [x] Fork nushell as seksh
- [x] Create `nu-seks` crate
- [x] Implement output scrubbing
- [x] Base64/hex encoding detection
- [x] Implement `getseks` built-in command
- [x] Implement `listseks` (list available secrets without values)

### Phase 2: Broker (IN PROGRESS)
- [x] Cloudflare Workers broker (`~/seks-broker/`)
- [x] REST API with bearer token auth
- [x] Encrypted secrets at rest
- [x] Web admin UI
- [x] Audit logging
- [ ] Deploy to production
- [ ] Wire seksh to broker endpoint

### Phase 3: Wrapped Commands (NEXT)
- [ ] `seksh-http` — HTTP requests with credential injection
- [ ] `seksh-git` — git operations with credential injection
- [ ] `seksh-curl` — curl wrapper (broker proxies request)

### Phase 4: Hardening (FUTURE)
- [ ] OS keychain integration (optional backend)
- [ ] Secret rotation support
- [ ] Rate limiting / anomaly detection

---

## Open Questions

1. ~~**Broker lifecycle**: Who starts the broker?~~ → Cloud-hosted, always available
2. ~~**Multi-agent**: One broker per agent, or shared?~~ → Shared, multi-tenant
3. **Secret scoping**: Per-command secrets vs session-wide?
4. **Failure mode**: What if broker is unavailable? (graceful degradation?)
5. **Local dev**: How does seksh discover broker URL? (env var? config file?)

---

*Document maintained in `seksh/docs/SEKS_DESIGN.md`*
