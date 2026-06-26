#!/usr/bin/env python3
import pathlib
import re
import sys

text = pathlib.Path("Cargo.toml").read_text(encoding="utf-8")
m = re.search(r'^version = "([^"]+)"', text, re.M)
if not m:
    print("ERROR: Could not find version in Cargo.toml", file=sys.stderr)
    sys.exit(1)
print(m.group(1))
