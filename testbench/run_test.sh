#!/usr/bin/env bash
# GFMX test bench: generate blueprint+noise certs, fingerprint them blind, match.
# Usage: ./run_test.sh [OUT_DIR] [extra gen_certs.py args, e.g. --seed 7 --blueprints 20]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
GFMX="${GFMX:-$HERE/../gfmx.py}"
OUT="${1:-$HERE/run}"; shift || true
rm -rf "$OUT"

echo "### 1. Generating certificates"
python3 "$HERE/gen_certs.py" --out "$OUT" "$@"

echo; echo "### 2. Fingerprinting (blind: only the certificate files are passed)"
python3 "$GFMX" --quiet --csv "$OUT/fingerprints.csv" "$OUT/certs"

echo; echo "### 3. Matching"
python3 "$HERE/match.py" "$OUT/truth.csv" "$OUT/fingerprints.csv"
