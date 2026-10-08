#!/usr/bin/env sh
# A time-boxed differential run (the plan's "10 minutes with no TS/Go/Rust disagreement"): fresh scanner corpora and
# interpreter corpora from the TS reference, seed after seed, each replayed by both ports. Stops at the first
# disagreement. Run from the b017-native root, with ../b017 checked out:  sh vectors/gen/differential.sh [seconds] [first seed]
set -e
SECS=${1:-600}
SEED=${2:-100}
ROOT=$(pwd)
RAW=$ROOT/vectors/raw
CFG=$ROOT/vectors/gen/vitest.static.config.mjs
mkdir -p "$RAW"
END=$(( $(date +%s) + SECS ))
scan=0; interp=0
while [ "$(date +%s)" -lt "$END" ]; do
  (cd ../b017 && NODE_OPTIONS=--max-old-space-size=8192 B017_FUZZ_CASES=1500 B017_FUZZ_SEED=$SEED B017_FUZZ_OUT=$RAW/diff-fuzz.json \
    node node_modules/vitest/vitest.mjs run fuzz --config "$CFG" >/dev/null 2>&1)
  (cd ../b017 && B017_INTERP_CASES=20000 B017_INTERP_SEED=$SEED B017_INTERP_OUT=$RAW/diff-interp.json \
    node node_modules/vitest/vitest.mjs run interp --config "$CFG" >/dev/null 2>&1)
  B017_FUZZ_FILE=$RAW/diff-fuzz.json cargo test -q -p b017 --release --test fuzz vectors_fuzz >/dev/null 2>&1 || { echo "seed $SEED: Rust scanner disagrees"; exit 1; }
  B017_INTERP_FILE=$RAW/diff-interp.json cargo test -q -p b017 --release --test interp vectors_interpreter >/dev/null 2>&1 || { echo "seed $SEED: Rust interpreter disagrees"; exit 1; }
  (cd go && B017_FUZZ_FILE=$RAW/diff-fuzz.json B017_INTERP_FILE=$RAW/diff-interp.json go test -count=1 -run 'TestVectorsFuzz$|TestVectorsInterpreter$' . >/dev/null 2>&1) || { echo "seed $SEED: Go disagrees"; exit 1; }
  scan=$((scan + 1500)); interp=$((interp + 20000))
  echo "seed $SEED ok (so far: $scan scanner cases, $interp interpreter cases)"
  SEED=$((SEED + 1))
done
echo "differential: ${SECS}s, $scan scanner cases and $interp interpreter cases, no disagreement"
