# SEKSH Wrapped Commands - Secure Secret Handling

## The Problem

The original `getseks` command exposes secrets to the shell's memory space:

```nushell
# UNSAFE: secret enters shell memory
^curl -H $"Authorization: Bearer (getseks github_token)" https://api.github.com/user
```

Once in shell memory, secrets can be exfiltrated via:
- String transforms (`split chars | str join "-"`)
- File writes (`save /tmp/secret.txt`)
- External commands (`^echo $secret`)
- Environment variable export to externals
- Oracle attacks (equality comparisons)

The scrubber catches some of these, but it's fundamentally a losing battle — you can't secure data that's already in untrusted memory.

## The Solution: Wrapped Commands

Wrapped commands keep secrets **internal**. The shell sees secret *names*, never *values*:

```nushell
# SAFE: secret never enters shell memory
seksh-http get https://api.github.com/user --auth-bearer github_token
```

The secret flow is:
```
Broker → seksh-http internal → HTTP request
(shell only sees: command args with secret NAMES + scrubbed response)
```

## Available Wrapped Commands

### seksh-http

Make HTTP requests with secrets injected internally.

```nushell
# Bearer token auth
seksh-http get https://api.github.com/user --auth-bearer github_token

# Basic auth (both user and pass are secret names)
seksh-http get https://db.example.com --auth-basic-user db_user --auth-basic-pass db_pass

# Custom secret headers
seksh-http post https://api.example.com/data \
  --header-secret 'X-Api-Key:my_api_key' \
  --data '{"foo": "bar"}'

# Mix secret and plain headers
seksh-http get $url \
  --header-secret 'Authorization:token' \
  --header 'Content-Type: application/json'
```

**Options:**
- `--auth-bearer <secret_name>` - Use secret as Bearer token
- `--auth-basic-user <secret_name>` - Basic auth username (requires --auth-basic-pass)
- `--auth-basic-pass <secret_name>` - Basic auth password
- `--header-secret <name:secret>` - Header with secret value (repeatable)
- `--header <name: value>` - Plain header (repeatable)
- `--data <body>` - Request body
- `--timeout <seconds>` - Request timeout (default: 30)
- `--insecure` - Allow insecure TLS

### listseks

List available secrets (names only, never values):

```nushell
> listseks
╭───┬──────────────────────╮
│ 0 │ github_token         │
│ 1 │ cloudflare_api_key   │
│ 2 │ notion_api_key       │
╰───┴──────────────────────╯

# Check if a secret exists
listseks | any {|name| $name == 'github_token'}  # true
```

## Security Model

### Trust Boundaries

```
┌─────────────────────────────────────────────────────┐
│  TRUSTED ZONE (secrets visible)                     │
│  ┌─────────────┐      ┌─────────────────────────┐   │
│  │   Broker    │ ───► │  Wrapped Command        │   │
│  │ (secrets.json)     │  (seksh-http, etc.)     │   │
│  └─────────────┘      └──────────┬──────────────┘   │
└──────────────────────────────────┼──────────────────┘
                                   │
                          ┌────────▼────────┐
                          │   HTTP Request  │
                          │  (with secret)  │
                          └────────┬────────┘
                                   │
┌──────────────────────────────────┼──────────────────┐
│  UNTRUSTED ZONE (secrets never visible)             │
│                          ┌───────▼───────┐          │
│                          │   Response    │          │
│                          │  (scrubbed)   │          │
│                          └───────┬───────┘          │
│                                  │                  │
│  ┌─────────────────────────────────────────────┐    │
│  │              Nushell Session                │    │
│  │  - Command arguments (secret NAMES only)   │    │
│  │  - Response body (scrubbed as defense)     │    │
│  └─────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
```

### Defense in Depth

1. **Primary**: Secrets never enter shell memory
2. **Secondary**: Response scrubbing catches echoed tokens
3. **Tertiary**: `getseks` still registers secrets for legacy code

## Deprecation of getseks

`getseks` is now deprecated. It still works but displays a warning.

**Migration:**

```nushell
# OLD (deprecated)
^curl -H $"Authorization: Bearer (getseks github_token)" $url

# NEW (secure)
seksh-http get $url --auth-bearer github_token
```

For commands that don't have wrapped equivalents yet, `getseks` remains available as a fallback, but understand the security trade-off.

## Adding New Wrapped Commands

To add a new wrapped command:

1. Create a new file in `crates/nu-cmd-seks/src/`
2. Implement the `Command` trait
3. Fetch secrets internally via `BrokerClient`
4. Register secrets with `register_named_secret()` for response scrubbing
5. Add to `lib.rs`

See `seksh_http.rs` as a reference implementation.

## Future Work

- `seksh-aws` - AWS CLI with credentials injected
- `seksh-git` - Git operations with token injection
- `seksh-ssh` - SSH with key/passphrase handling
- Config file for domain → secret mappings (auto-auth)
