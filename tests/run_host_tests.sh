#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cc -DVT_HOST -Wno-deprecated-declarations -Wall -Wextra -Werror -std=c99 -Isrc \
  src/protocol.c tests/test_protocol.c -lcrypto -o /tmp/vitatunnel_protocol_test
/tmp/vitatunnel_protocol_test tests/sample_config.ini tests/sample_manifest.txt
python3 -m py_compile tools/make_manifest.py
