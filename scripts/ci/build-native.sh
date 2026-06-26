#!/usr/bin/env bash
set -euo pipefail

# Build Rust cdylib in release mode
cargo build --lib --release
