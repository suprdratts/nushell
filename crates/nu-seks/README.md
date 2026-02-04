# nu-seks

SEKS (Secure Execution Kernel for Shells) security module for Nushell.

## Overview

This crate provides the security infrastructure for `seksh`, a security-focused fork of nushell. The primary feature is **token scrubbing** - automatic detection and redaction of sensitive values in shell output.

## Features

### Secret Registry

A thread-safe registry for storing sensitive values:

```rust
use nu_seks::{register_secret, clear_secrets};

// Register API tokens, passwords, etc.
register_secret("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
register_secret("sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
```

### Output Scrubbing

Automatically replace registered secrets with `[REDACTED]`:

```rust
use nu_seks::{register_secret, scrub_output};

register_secret("my-api-token");

let output = scrub_output("curl -H 'Authorization: Bearer my-api-token' ...");
// Returns: "curl -H 'Authorization: Bearer [REDACTED]' ..."
```

### Encoding-Aware Detection

Secrets are also detected in common encodings:

- **Base64**: Standard base64 encoding
- **Hex**: Both lowercase and uppercase hexadecimal

```rust
use nu_seks::{register_secret, scrub_output};

register_secret("secret");

// Original form
scrub_output("password=secret"); 
// → "password=[REDACTED]"

// Base64 encoded (c2VjcmV0)
scrub_output("token=c2VjcmV0");
// → "token=[REDACTED]"

// Hex encoded (736563726574)
scrub_output("hex=736563726574");
// → "hex=[REDACTED]"
```

## Design Philosophy

Token scrubbing is **defense-in-depth**. It's not bulletproof—a determined attacker could potentially circumvent it through:

- Unicode confusables or homoglyphs
- Custom encodings
- String manipulation that breaks up the token

However, it significantly raises the bar by preventing **accidental** exposure in:

- ✅ Command output that gets logged or shared
- ✅ Shell history that might be synced or backed up  
- ✅ Error messages containing sensitive context
- ✅ Debug output during development
- ✅ Screenshots or screen recordings

The goal is to make it **harder to accidentally leak secrets**, not to provide cryptographic guarantees.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     User Command                            │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  Nushell Pipeline                           │
│  (Commands execute, producing PipelineData)                 │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  Output Rendering                           │
│  (print_table, print_raw, etc.)                            │
│                           │                                 │
│              ┌────────────▼────────────┐                   │
│              │    SEKS Scrubbing       │                   │
│              │  ┌──────────────────┐   │                   │
│              │  │ Secret Registry  │   │                   │
│              │  │  • raw secrets   │   │                   │
│              │  │  • base64 forms  │   │                   │
│              │  │  • hex forms     │   │                   │
│              │  └──────────────────┘   │                   │
│              └─────────────────────────┘                   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   Terminal Output                           │
│  (Secrets replaced with [REDACTED])                         │
└─────────────────────────────────────────────────────────────┘
```

## Integration Points

The scrubbing hooks into nushell's output pipeline at key points:

1. **`PipelineData::print_table`** - Table-formatted output
2. **`PipelineData::print_raw`** - Raw/unformatted output  
3. **`ByteStream::print`** - Streaming byte output

## API Reference

### Core Functions

| Function | Description |
|----------|-------------|
| `register_secret(s)` | Add a secret to the global registry |
| `scrub_output(text)` | Replace secrets in a string with `[REDACTED]` |
| `clear_secrets()` | Remove all registered secrets |
| `secret_count()` | Get number of registered secrets |

### Registry Type

For isolated use cases:

```rust
use nu_seks::{SecretRegistry, scrub_output_with_registry};

let registry = SecretRegistry::new();
registry.register("my-secret");

let output = scrub_output_with_registry("has my-secret", &registry);
```

## Testing

```bash
cd crates/nu-seks
cargo test
```

## Future Enhancements

- [ ] Additional encodings (URL encoding, unicode escapes)
- [ ] Secret rotation support (remove old, add new)
- [ ] Integration with system keychains
- [ ] Secret auto-detection from environment variables
- [ ] Configurable redaction markers
- [ ] Performance optimizations for large outputs (Aho-Corasick)

## Security Considerations

- **Minimum length**: Secrets shorter than 4 characters are rejected to reduce false positives
- **Thread safety**: The registry uses `parking_lot::RwLock` for concurrent access
- **Memory**: Secrets are stored in memory; consider using secure memory in future versions
- **Timing**: The current implementation does not protect against timing side-channels

## License

MIT - Same as nushell
