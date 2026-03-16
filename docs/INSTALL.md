# seksh Installation Guide

**seksh** (Secure Execution Kernel for Shells) is a nushell fork that isolates credentials from AI agents.

## Prerequisites

- **Rust toolchain** (1.70+): Install via [rustup](https://rustup.rs/)
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

- **macOS:** Xcode Command Line Tools
  ```bash
  xcode-select --install
  ```

## Building from Source

```bash
# Clone the repository
git clone https://github.com/SEKSBot/seksh.git
cd seksh

# Checkout the seks-shell branch
git checkout seks-shell

# Build release binary (~5-10 minutes first time)
cargo build --release

# Verify the build
file target/release/nu
# Should output: Mach-O 64-bit executable arm64 (on Apple Silicon)

./target/release/nu --version
# Should output: 0.110.1 (or similar)
```

The binary is at `target/release/nu` (~47-49MB).

## Broker Configuration

seksh connects to a credential broker that holds your secrets. Configure it in nushell's env file:

### 1. Find your config directory

```bash
./target/release/nu -c '$nu.env-path'
# macOS: ~/Library/Application Support/nushell/env.nu
```

### 2. Create/edit env.nu

```bash
mkdir -p "~/Library/Application Support/nushell"
```

Add to `env.nu`:

```nu
# SEKS Broker Configuration
$env.SEKS_BROKER_URL = "https://seks-broker.stcredzero.workers.dev"
$env.SEKS_AGENT_TOKEN = "seks_agent_YOUR_TOKEN_HERE"
```

### 3. Get your agent token

Contact your broker administrator for an agent token, or if you're running your own broker, create one via the web UI.

### 4. Set file permissions

```bash
chmod 600 "~/Library/Application Support/nushell/env.nu"
```

## Verify Installation

```bash
# Start seksh
./target/release/nu

# List available secrets (without exposing values)
listseks
# Should show: secret1, secret2, ... (names only)

# Test a secret fetch (value is auto-scrubbed from output)
echo (getseks 'some_secret')
# Should show: <secret:some_secret>
```

## Optional: Add to PATH

```bash
# Create symlink
mkdir -p ~/.local/bin
ln -sf ~/seksh/target/release/nu ~/.local/bin/seksh

# Add to PATH (in ~/.zshrc or ~/.bashrc)
export PATH="$HOME/.local/bin:$PATH"

# Now you can run:
seksh
```

## Multi-Tenancy

Each macOS user account should have:
- Their own `~/Library/Application Support/nushell/env.nu`
- Their own unique `SEKS_AGENT_TOKEN`

The broker enforces isolation — each token only accesses that agent's secrets.

## Troubleshooting

### "Connection refused" or broker errors
- Check `SEKS_BROKER_URL` is correct
- Verify your token is valid
- Test broker connectivity: `curl -I $SEKS_BROKER_URL`

### Build fails with missing dependencies
- Ensure Rust is up to date: `rustup update`
- On macOS, install Xcode tools: `xcode-select --install`

### listseks returns empty
- Verify your token has secrets assigned in the broker
- Check token is correctly set: `echo $env.SEKS_AGENT_TOKEN`

## Next Steps

- Read [SEKS_DESIGN.md](./SEKS_DESIGN.md) for architecture details
- Read [WRAPPED_COMMANDS.md](./WRAPPED_COMMANDS.md) for seksh-http and seksh-git usage
