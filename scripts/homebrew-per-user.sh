#!/bin/bash
# homebrew-per-user.sh — Migrate from shared /opt/homebrew to per-user ~/.brew
#
# Run as the user who needs their own Homebrew installation.
# Does NOT touch /opt/homebrew — that can be removed later.

set -euo pipefail

# Prevent git from prompting for credentials (fail fast instead of hanging)
export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=false
# Disable credential helpers entirely (prevent osxkeychain from blocking)
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null

HOMEBREW_PREFIX="$HOME/.brew"
LEAVES_FILE="$HOME/.brew-leaves.txt"
NPM_GLOBALS_FILE="$HOME/.npm-globals.txt"
CASKS_FILE="$HOME/.brew-casks.txt"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[x]${NC} $1"; exit 1; }

# Step 1: Save current leaves if old brew exists (skip if already saved)
if [[ -s "$LEAVES_FILE" ]]; then
    log "Using existing leaves file: $LEAVES_FILE ($(wc -l < "$LEAVES_FILE" | tr -d ' ') formulae)"
elif command -v brew &>/dev/null; then
    log "Saving current Homebrew leaves to $LEAVES_FILE"
    brew leaves > "$LEAVES_FILE"
    log "Saved $(wc -l < "$LEAVES_FILE" | tr -d ' ') formulae"
    
    log "Saving current Homebrew casks to $CASKS_FILE"
    brew list --cask > "$CASKS_FILE" 2>/dev/null || touch "$CASKS_FILE"
    log "Saved $(wc -l < "$CASKS_FILE" | tr -d ' ') casks"
else
    warn "No existing brew found — starting fresh"
    touch "$LEAVES_FILE"
    touch "$CASKS_FILE"
fi

# Step 1b: Save npm globals if npm exists
if command -v npm &>/dev/null; then
    log "Saving npm global packages to $NPM_GLOBALS_FILE"
    npm list -g --depth=0 2>/dev/null | \
        grep -E "^[+\`]--" | \
        sed 's/^[+`]-- //' | \
        cut -d@ -f1 | \
        grep -v "^npm$" > "$NPM_GLOBALS_FILE" || true
    log "Saved $(wc -l < "$NPM_GLOBALS_FILE" | tr -d ' ') npm globals"
else
    touch "$NPM_GLOBALS_FILE"
fi

# Step 2: Check if already installed
if [[ -d "$HOMEBREW_PREFIX/Homebrew" ]]; then
    warn "$HOMEBREW_PREFIX/Homebrew already exists"
    read -p "Remove and reinstall? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$HOMEBREW_PREFIX"
    else
        err "Aborting"
    fi
fi

# Step 3: Clone Homebrew
log "Installing Homebrew to $HOMEBREW_PREFIX"
mkdir -p "$HOMEBREW_PREFIX"
git clone --depth=1 https://github.com/Homebrew/brew "$HOMEBREW_PREFIX/Homebrew"

# Step 4: Create bin symlink
mkdir -p "$HOMEBREW_PREFIX/bin"
ln -sf "$HOMEBREW_PREFIX/Homebrew/bin/brew" "$HOMEBREW_PREFIX/bin/brew"

# Step 5: Set up environment for this session
export PATH="$HOMEBREW_PREFIX/bin:$PATH"
export HOMEBREW_PREFIX
export HOMEBREW_CELLAR="$HOMEBREW_PREFIX/Cellar"
export HOMEBREW_REPOSITORY="$HOMEBREW_PREFIX/Homebrew"

# Verify
log "Verifying installation..."
"$HOMEBREW_PREFIX/bin/brew" --version

# Step 6: Update
log "Updating Homebrew..."
"$HOMEBREW_PREFIX/bin/brew" update

# Step 7: Reinstall leaves
if [[ -s "$LEAVES_FILE" ]]; then
    log "Reinstalling packages from $LEAVES_FILE"
    log "This may take a while..."
    
    # Install each package, continue on failure
    while IFS= read -r pkg; do
        [[ -z "$pkg" ]] && continue
        log "Installing $pkg..."
        "$HOMEBREW_PREFIX/bin/brew" install "$pkg" || warn "Failed to install $pkg — continuing"
    done < "$LEAVES_FILE"
fi

# Step 8: Shell config snippet
SHELL_SNIPPET='
# Per-user Homebrew
export HOMEBREW_PREFIX="$HOME/.brew"
export HOMEBREW_CELLAR="$HOMEBREW_PREFIX/Cellar"
export HOMEBREW_REPOSITORY="$HOMEBREW_PREFIX/Homebrew"
export PATH="$HOMEBREW_PREFIX/bin:$HOMEBREW_PREFIX/sbin:$PATH"
export MANPATH="$HOMEBREW_PREFIX/share/man${MANPATH+:$MANPATH}:"
export INFOPATH="$HOMEBREW_PREFIX/share/info:${INFOPATH:-}"
'

log "Add this to your shell config (~/.zshrc or ~/.bashrc):"
echo "$SHELL_SNIPPET"

# Optionally append to zshrc
if [[ -f "$HOME/.zshrc" ]]; then
    read -p "Append to ~/.zshrc? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "$SHELL_SNIPPET" >> "$HOME/.zshrc"
        log "Added to ~/.zshrc — restart your shell or run: source ~/.zshrc"
    fi
fi

# Step 9: Reinstall npm globals
if [[ -s "$NPM_GLOBALS_FILE" ]] && command -v "$HOMEBREW_PREFIX/bin/npm" &>/dev/null; then
    log "Reinstalling npm global packages..."
    while IFS= read -r pkg; do
        [[ -z "$pkg" ]] && continue
        log "Installing npm global: $pkg"
        "$HOMEBREW_PREFIX/bin/npm" install -g "$pkg" || warn "Failed to install $pkg"
    done < "$NPM_GLOBALS_FILE"
elif [[ -s "$NPM_GLOBALS_FILE" ]]; then
    warn "npm not found in new Homebrew — skipping npm globals"
    warn "Install node first, then run: cat $NPM_GLOBALS_FILE | xargs npm install -g"
fi

log "Done! Homebrew installed to $HOMEBREW_PREFIX"
log "Installed packages: $("$HOMEBREW_PREFIX/bin/brew" list --formula | wc -l | tr -d ' ') formulae"

if [[ -s "$NPM_GLOBALS_FILE" ]]; then
    log "npm globals saved in $NPM_GLOBALS_FILE"
fi
if [[ -s "$CASKS_FILE" ]]; then
    log "Casks saved in $CASKS_FILE (install manually with: brew install --cask \$(cat $CASKS_FILE))"
fi
