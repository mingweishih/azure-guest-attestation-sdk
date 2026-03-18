#!/usr/bin/env bash
set -euo pipefail

echo "Checking for rustup..."
if ! command -v rustup >/dev/null 2>&1; then
  echo "rustup not found. Installing..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  export PATH="$HOME/.cargo/bin:$PATH"
else
  echo "rustup found."
fi

echo "Ensuring stable toolchain is installed and active..."
rustup toolchain install stable
rustup default stable

echo "Installing development tools via cargo..."
if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found in PATH after rustup install - restart your shell or source ~/.cargo/env"
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
echo "Note: For Windows builds you may need MSVC build tools (Visual Studio Build Tools)."
echo "      vTPM tests require Perl for the vendored OpenSSL build (Strawberry Perl on Windows)."