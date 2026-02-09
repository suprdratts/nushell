# SEKS Integration Contract

**Version:** 1.0  
**Date:** 2026-02-08  
**Authors:** Síofra, AeonByte

This document defines the integration contract between seksh (the shell) and seks-broker (the credential vault). Both sides must implement to this spec.

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SEKS_BROKER_URL` | No | `http://localhost:8787` | Base URL of the broker |
| `SEKS_AGENT_TOKEN` | Yes | — | Bearer token for agent authentication |

**Example:**
```bash
export SEKS_BROKER_URL=http://seks-broker:8787
export SEKS_AGENT_TOKEN=seks_agent_abc123def456
```

---

## Authentication

All API requests must include the agent token as a Bearer token:

```
Authorization: Bearer seks_agent_abc123def456
```

**Token format:** `seks_agent_<random>` (recommended: 32+ chars of alphanumeric)

---

## API Endpoints

### Health Check

```
GET /v1/health
```

**Response:**
```json
{
  "status": "ok"
}
```

No authentication required.

---

### Get Secret

```
POST /v1/secrets/get
Content-Type: application/json
Authorization: Bearer <agent_token>

{
  "name": "ANTHROPIC_API_KEY"
}
```

**Success Response:**
```json
{
  "ok": true,
  "value": "sk-ant-..."
}
```

**Error Response (not found):**
```json
{
  "ok": false,
  "error": "Secret not found: ANTHROPIC_API_KEY"
}
```

**Error Response (unauthorized):**
```json
{
  "ok": false,
  "error": "Unauthorized"
}
```

---

### List Secrets

```
POST /v1/secrets/list
Content-Type: application/json
Authorization: Bearer <agent_token>

{}
```

**Response:**
```json
{
  "ok": true,
  "secrets": [
    { "name": "ANTHROPIC_API_KEY", "provider": "anthropic" },
    { "name": "OPENAI_API_KEY", "provider": "openai" },
    { "name": "GITHUB_TOKEN", "provider": null }
  ]
}
```

The `provider` field is optional metadata (not used by seksh).

---

## Multi-Agent Architecture

One account can have multiple agents sharing one broker:

```
┌─────────────────────────────────────────────────────────────────┐
│                    CUSTOMER ACCOUNT                              │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    seks-broker                            │   │
│  │  Secrets: ANTHROPIC_KEY, OPENAI_KEY, GITHUB_TOKEN        │   │
│  │  Agent tokens: agent_work, agent_home, agent_mobile      │   │
│  └──────────────────────────────────────────────────────────┘   │
│         ▲              ▲              ▲                          │
│         │              │              │                          │
│  ┌──────┴───┐   ┌──────┴───┐   ┌──────┴───┐                     │
│  │ seksbot  │   │ seksbot  │   │ seksbot  │                     │
│  │ (work)   │   │ (home)   │   │ (mobile) │                     │
│  │ token:   │   │ token:   │   │ token:   │                     │
│  │ work     │   │ home     │   │ mobile   │                     │
│  └──────────┘   └──────────┘   └──────────┘                     │
└─────────────────────────────────────────────────────────────────┘
```

**Rules:**
- All agents in an account share the same secrets
- Each agent has its own token (for audit logging)
- Broker tracks which agent accessed which secret

---

## Docker Compose Example

```yaml
version: "3.8"

services:
  seksbot:
    image: ghcr.io/seksbot/seksbot:latest
    environment:
      - SEKS_BROKER_URL=http://seks-broker:8787
      - SEKS_AGENT_TOKEN=${AGENT_TOKEN}
    depends_on:
      - seks-broker

  seks-broker:
    image: ghcr.io/seksbot/seks-broker:latest
    environment:
      - MASTER_KEY=${BROKER_MASTER_KEY}
    volumes:
      - broker-data:/data
    ports:
      - "8787:8787"

volumes:
  broker-data:
```

---

## seksh Binary Distribution

Published as GitHub Release artifacts:

```
https://github.com/SEKSBot/seksh/releases/latest/download/seksh-linux-x64
https://github.com/SEKSBot/seksh/releases/latest/download/seksh-linux-arm64
https://github.com/SEKSBot/seksh/releases/latest/download/seksh-darwin-x64
https://github.com/SEKSBot/seksh/releases/latest/download/seksh-darwin-arm64
```

**In Dockerfile:**
```dockerfile
ARG TARGETARCH
RUN curl -L https://github.com/SEKSBot/seksh/releases/latest/download/seksh-linux-${TARGETARCH} \
    -o /usr/local/bin/seksh && chmod +x /usr/local/bin/seksh
```

---

## Error Handling

| HTTP Status | Meaning | seksh Behavior |
|-------------|---------|----------------|
| 200 | Success | Parse response |
| 401 | Unauthorized | Return `BrokerError::NoToken` or invalid token |
| 404 | Secret not found | Return `BrokerError::SecretNotFound` |
| 500 | Broker error | Return `BrokerError::BrokerError` |
| Connection refused | Broker down | Return `BrokerError::ConnectionFailed` |

---

## Changelog

### v1.0 (2026-02-08)
- Initial contract definition
- HTTP REST API (replaces Unix socket)
- Multi-agent support documented
