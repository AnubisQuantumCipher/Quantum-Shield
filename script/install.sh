#!/usr/bin/env bash
set -euo pipefail

echo "==> Checking prerequisites"
if ! command -v rustup >/dev/null 2>&1; then
  echo "Installing Rust (rustup) ..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck disable=SC1090
  source "$HOME/.cargo/env"
fi
rustc --version >/dev/null
cargo --version >/dev/null

echo "==> Building and installing CLI"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

cd "$REPO_ROOT"
cargo install --path crates/qsfs-cli --force

echo "==> Ensuring PATH includes ~/.cargo/bin"
if ! command -v qsfs >/dev/null 2>&1; then
  case "${SHELL:-}" in
    */zsh)
      grep -q 'export PATH="$HOME/.cargo/bin:$PATH"' "$HOME/.zprofile" 2>/dev/null || \
        printf '\nexport PATH="$HOME/.cargo/bin:$PATH"\n' >> "$HOME/.zprofile"
      ;;
    */bash)
      grep -q 'export PATH="$HOME/.cargo/bin:$PATH"' "$HOME/.bash_profile" 2>/dev/null || \
        printf '\nexport PATH="$HOME/.cargo/bin:$PATH"\n' >> "$HOME/.bash_profile"
      ;;
    *) ;;
  esac
  export PATH="$HOME/.cargo/bin:$PATH"
fi

echo "==> Installed binaries"
command -v qsfs || true
command -v qsfs-keygen || true
qsfs --version || true

echo "==> Done. Next, run: script/setup.sh"

