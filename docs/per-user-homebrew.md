# Per-User Homebrew Installation

Isolate Homebrew installations per-user instead of sharing `/opt/homebrew`. Each user gets their own `~/.brew` with independent formulae and casks.

## Why?

- **Agent isolation**: Each agent user has its own tools without write access to shared paths
- **No permission conflicts**: Users can install/update packages independently
- **Reproducibility**: User environments are self-contained

## Quick Start

```bash
# Download and run the migration script
curl -fsSL https://raw.githubusercontent.com/SEKSBot/seksh/main/scripts/homebrew-per-user.sh | bash
```

Or if you have the script locally:

```bash
bash ~/.openclaw/workspace/scripts/homebrew-per-user.sh
```

## What It Does

1. **Saves existing packages** (if migrating from `/opt/homebrew`)
   - Formulae → `~/.brew-leaves.txt`
   - Casks → `~/.brew-casks.txt`
   - npm globals → `~/.npm-globals.txt`

2. **Installs Homebrew to `~/.brew`**
   - Clones Homebrew/brew to `~/.brew/Homebrew`
   - Creates symlinks in `~/.brew/bin`

3. **Reinstalls packages** from saved lists

4. **Configures shell** (adds to `~/.zshrc` or `~/.bashrc`)

## Manual Setup

If you prefer manual installation:

```bash
# Clone Homebrew
git clone --depth=1 https://github.com/Homebrew/brew ~/.brew/Homebrew

# Create directory structure
mkdir -p ~/.brew/bin ~/.brew/Cellar
ln -sf ~/.brew/Homebrew/bin/brew ~/.brew/bin/brew

# Add to PATH (add to ~/.zshrc)
export HOMEBREW_PREFIX="$HOME/.brew"
export HOMEBREW_CELLAR="$HOMEBREW_PREFIX/Cellar"
export HOMEBREW_REPOSITORY="$HOMEBREW_PREFIX/Homebrew"
export PATH="$HOMEBREW_PREFIX/bin:$HOMEBREW_PREFIX/sbin:$PATH"
export MANPATH="$HOMEBREW_PREFIX/share/man${MANPATH+:$MANPATH}:"
export INFOPATH="$HOMEBREW_PREFIX/share/info:${INFOPATH:-}"

# Optional: Install casks to ~/Applications instead of /Applications
export HOMEBREW_CASK_OPTS="--appdir=$HOME/Applications"
mkdir -p ~/Applications

# Update and install packages
brew update
brew install <your-packages>
```

## Casks That Need sudo

Some casks require system-level installation and will fail without sudo:

- `anaconda` (system Python paths)
- `xquartz` (X11 server, system integration)
- `copilot-for-xcode` (Xcode plugin)
- Anything with a `.pkg` installer

For these, either:
1. Install manually with `sudo brew install --cask <name>`
2. Or skip them if not needed

## After Migration

```bash
# Verify installation
~/.brew/bin/brew --version
~/.brew/bin/brew list

# Open new terminal or source your shell config
source ~/.zshrc  # or ~/.bashrc

# Now 'brew' uses your per-user installation
which brew  # should show ~/.brew/bin/brew
```

## Cleanup (Optional)

Once everything works, you can remove the shared installation:

```bash
# Only after verifying your per-user brew works!
sudo rm -rf /opt/homebrew
```

## Troubleshooting

**brew command not found after install**
- Open a new terminal, or run `source ~/.zshrc`

**Permission denied on /opt/homebrew**
- Good! That means your PATH is still pointing to the old location
- Ensure `~/.brew/bin` comes first in your PATH

**Cask installed to wrong location**
- Set `HOMEBREW_CASK_OPTS="--appdir=$HOME/Applications"` before installing
