#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${PACKAGE_VERSION:-}" ]]; then
    echo "ERROR: PACKAGE_VERSION environment variable not set" >&2
    exit 1
fi

if [[ -z "${NATIVE_ASSETS_DIR:-}" ]]; then
    echo "ERROR: NATIVE_ASSETS_DIR environment variable not set" >&2
    exit 1
fi

dotnet pack "interop/IrcxSspi.Native/IrcxSspi.Native.csproj" \
    --configuration Release \
    --output artifacts/nuget \
    -p:PackageVersion="$PACKAGE_VERSION" \
    -p:NativeAssetsDir="$NATIVE_ASSETS_DIR"

echo "NuGet package created successfully"
