#!/usr/bin/env sh
# Fetch the bsv-sdk crate at the pinned base and apply b017-native's fixes (until they are merged upstream).
# The Rust crate (rust/) uses third_party/bsv-rust-sdk as a path dependency.
set -e
cd "$(dirname "$0")"
BASE=$(cat patches/BASE)
if [ ! -d bsv-rust-sdk/.git ]; then git clone -q https://github.com/b1narydt/bsv-rust-sdk bsv-rust-sdk; fi
cd bsv-rust-sdk
if ! git rev-parse -q --verify b017-codesep >/dev/null; then
  git checkout -q -b b017-codesep "$BASE"
  git -c user.name=b017-native -c user.email=b017-native@users.noreply.github.com am -q ../patches/*.patch
fi
git checkout -q b017-codesep

