#!/usr/bin/env bash
set -euo pipefail

# GitHub-hosted runner images ship SDKs and language toolchains this build
# never uses. The rodin OrangeFox build is disk-bound, not CPU-bound, so
# reclaiming them decides whether a runner can hold the source tree at all.
# Safe only on an ephemeral hosted image.

if ! sudo -n true; then
  echo "Passwordless sudo is required to reclaim hosted-image space." >&2
  exit 1
fi

workspace="${GITHUB_WORKSPACE:-$PWD}"
tool_cache="${RUNNER_TOOL_CACHE:-${AGENT_TOOLSDIRECTORY:-/opt/hostedtoolcache}}"
unused_paths=(
  /usr/local/lib/android
  /usr/share/dotnet
  /opt/ghc
  /usr/local/.ghcup
  /usr/local/rustup
  /usr/local/cargo
  /usr/share/swift
  /opt/google
  /opt/microsoft
  /usr/local/share/chromium
  /usr/local/share/boost
  "${tool_cache}"
)

echo "Filesystem before reclaim:"
df -h "$workspace"

printf 'Removing unused hosted-image paths:\n'
printf '  %s\n' "${unused_paths[@]}"
sudo rm -rf -- "${unused_paths[@]}"

if command -v docker >/dev/null 2>&1; then
  sudo docker system prune --all --force --volumes || true
fi

sudo apt-get clean || true
sudo rm -rf /var/lib/apt/lists/* || true

echo "Filesystem after reclaim:"
df -h "$workspace"
echo "--- largest remaining host directories ---"
sudo du -sh /usr/share /usr/lib /opt /usr/local /home/runner 2>/dev/null | sort -hr | head -10 || true
