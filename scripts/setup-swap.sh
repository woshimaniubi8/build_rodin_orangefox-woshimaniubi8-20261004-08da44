#!/usr/bin/env bash
set -euo pipefail

# Add swap toward the recommended amount without consuming the filesystem space
# reserved for repo sync. The hard minimum is sufficient for build-lowmem.sh.
minimum_gib="${MIN_SWAP_GIB:-12}"
preferred_gib="${PREFERRED_SWAP_GIB:-16}"
current_kib="$(awk '/^SwapTotal:/ { print $2 }' /proc/meminfo)"
minimum_kib=$((minimum_gib * 1024 * 1024))
preferred_kib=$((preferred_gib * 1024 * 1024))
if (( preferred_kib < minimum_kib )); then
  echo "Preferred swap (${preferred_gib} GiB) is below the required minimum (${minimum_gib} GiB)." >&2
  exit 1
fi
if (( current_kib >= preferred_kib )); then
  free -h
  exit 0
fi

swap_path="${SWAP_PATH:-$RUNNER_TEMP/rodin-build.swap}"
install -d "$(dirname "$swap_path")"
available_kib="$(df -Pk "$(dirname "$swap_path")" | awk 'NR == 2 { print $4 }')"
reserved_kib="${MIN_FREE_KIB:-0}"
space_for_swap_kib=$((available_kib - reserved_kib))
preferred_extra_kib=$((preferred_kib - current_kib + 32768))

if (( preferred_extra_kib <= space_for_swap_kib )); then
  target_kib="$preferred_kib"
else
  if (( current_kib >= minimum_kib )); then
    echo "WARNING: keeping ${minimum_gib} GiB minimum swap; not enough disk headroom to reach ${preferred_gib} GiB without cutting into the sync reserve." >&2
    free -h
    exit 0
  fi
  minimum_extra_kib=$((minimum_kib - current_kib + 32768))
  if (( minimum_extra_kib > space_for_swap_kib )); then
    echo "ERROR: cannot reach the ${minimum_gib} GiB swap minimum while preserving ${reserved_kib} KiB for source sync." >&2
    exit 1
  fi
  target_kib="$minimum_kib"
  echo "WARNING: disk headroom allows the ${minimum_gib} GiB minimum but not the ${preferred_gib} GiB preferred swap." >&2
fi

deficit_kib=$((target_kib - current_kib + 32768))
extra_bytes=$((deficit_kib * 1024))
fallocate -l "$extra_bytes" "$swap_path"
chmod 600 "$swap_path"
mkswap "$swap_path"
sudo swapon "$swap_path"
current_kib="$(awk '/^SwapTotal:/ { print $2 }' /proc/meminfo)"
if (( current_kib < minimum_kib )); then
  echo "ERROR: swap setup finished below the required ${minimum_gib} GiB minimum." >&2
  exit 1
fi
free -h
