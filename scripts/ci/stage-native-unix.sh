#!/usr/bin/env bash
set -euo pipefail
RID="$1"
BINARY="$2"
mkdir -p "staging/$RID"
cp "target/release/$BINARY" "staging/$RID/$BINARY"
echo "Staged $BINARY to staging/$RID"
