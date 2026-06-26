#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    echo "ERROR: GITHUB_TOKEN environment variable not set" >&2
    exit 1
fi

if [[ -z "${GITHUB_REPOSITORY_OWNER:-}" ]]; then
    echo "ERROR: GITHUB_REPOSITORY_OWNER environment variable not set" >&2
    exit 1
fi

NuGET_SOURCE="https://nuget.pkg.github.com/$GITHUB_REPOSITORY_OWNER/index.json"

dotnet nuget push artifacts/nuget/*.nupkg \
    --source "$NuGET_SOURCE" \
    --api-key "$GITHUB_TOKEN" \
    --skip-duplicate

echo "Package published to GitHub Packages"
