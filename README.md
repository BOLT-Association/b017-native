# b017-native

Go and Rust transcriptions of [b017](https://github.com/BOLT-Association/b017) (the BOLT layer-1 token
templates and off-chain scanner), function for function, held to the TypeScript reference by shared vectors.

- `vectors/`: recorded from the reference's own test suite (`vectors/gen`), plus static data. See PROGRESS.md.
- `go/`: Go module `github.com/BOLT-Association/b017-native/go` (package `b017`), on go-sdk.
- `rust/`: crate `b017`, on `bsv-sdk` (patched, `third_party/setup.sh`, until the fix is merged upstream).
