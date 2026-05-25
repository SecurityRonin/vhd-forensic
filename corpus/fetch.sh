#!/usr/bin/env bash
# Generate VHD corpus images using qemu-img.
# Requires: qemu-utils (sudo apt-get install -y qemu-utils)
set -euo pipefail

DEST="$(cd "$(dirname "$0")" && pwd)"

# Dynamic VHD (most common type)
qemu-img create -f vpc "${DEST}/dynamic.vhd" 10M

# Fixed VHD (pre-allocated)
qemu-img create -f vpc -o subformat=fixed "${DEST}/fixed.vhd" 512K
