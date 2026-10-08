#!/usr/bin/env sh
# Fetch the bsv-sdk crate and go-sdk at their pinned bases and apply b017-native's fixes (until merged upstream).
# The Rust crate (rust/) uses third_party/bsv-rust-sdk as a path dependency; go/go.mod replaces go-sdk
# with third_party/go-sdk.
set -e
cd "$(dirname "$0")"
BASE=$(cat patches/BASE)
if [ ! -d bsv-rust-sdk/.git ]; then git clone -q https://github.com/b1narydt/bsv-rust-sdk bsv-rust-sdk; fi
cd bsv-rust-sdk
if ! git rev-parse -q --verify b017-codesep >/dev/null; then
  git checkout -q -b b017-codesep "$BASE"
  git am -q ../patches/*.patch
fi
git checkout -q b017-codesep

# go-sdk at v1.7.1 with b017-native's interpreter fix; go/go.mod replaces the module with this clone.
cd ..
GO_BASE=$(cat go-sdk-patches/BASE)
if [ ! -d go-sdk/.git ]; then git clone -q https://github.com/bsv-blockchain/go-sdk go-sdk; fi
cd go-sdk
if ! git rev-parse -q --verify b017 >/dev/null; then
  git checkout -q -b b017 "$GO_BASE"
  git am -q ../go-sdk-patches/*.patch
fi
git checkout -q b017
