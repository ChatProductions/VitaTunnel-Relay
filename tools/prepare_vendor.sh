#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
PIN=4af7eb1c6f924de5a982248dc4e69ad962c15377
mkdir -p vendor
if [ ! -d vendor/installer/.git ]; then
  git clone https://github.com/theheroGAC/Vita-VPKInstaller-Direct.git vendor/installer
fi
git -C vendor/installer fetch origin "$PIN"
git -C vendor/installer checkout --detach "$PIN"
# Vendor source files are MPL-2.0 and remain unmodified. Keep upstream LICENSE.
echo "Pinned installer at $(git -C vendor/installer rev-parse HEAD)"
