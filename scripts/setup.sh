#!/usr/bin/env bash
set -euo pipefail

echo "Checking for rustup..."
if ! command -v rustup >/dev/null 2>&1; then
  echo "rustup not found. Installing..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # Source the env file that rustup creates so cargo/rustup are available
  # for the remainder of this script.
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
else
  echo "rustup found."
fi

# Ensure cargo is on PATH (covers the case where ~/.cargo/env wasn't
# sourced in the current shell yet).
if ! command -v cargo >/dev/null 2>&1; then
  if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
  fi
fi

echo "Ensuring stable toolchain is installed and active..."
rustup toolchain install stable
rustup default stable

echo "Installing development tools via cargo..."
if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: cargo not found in PATH after rustup install."
  echo "  Please run:  source \"\$HOME/.cargo/env\"  (or restart your shell)"
  exit 1
else
  echo "Installing cargo-nextest (recommended test runner)..."
  cargo install cargo-nextest --locked 2>/dev/null || echo "  cargo-nextest install failed (non-fatal)"
fi

echo ""
echo "Developer tool setup complete."
echo ""
echo "Quick start:"
echo "  cargo build                 # Build all crates"
echo "  cargo nt                    # Run tests with nextest + vTPM"
echo ""
echo "IMPORTANT: If this is a fresh install, run the following in your current"
echo "           shell (or restart it) so that cargo is on your PATH:"
echo ""
echo "  source \"\$HOME/.cargo/env\""
echo ""
echo "Note: For Windows builds you may need MSVC build tools (Visual Studio Build Tools)."
echo "      vTPM tests require Perl for the vendored OpenSSL build (Strawberry Perl on Windows)."