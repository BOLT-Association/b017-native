module github.com/BOLT-Association/b017-native/go

go 1.26.0

require (
	github.com/bsv-blockchain/go-sdk v1.7.1
	golang.org/x/crypto v0.57.0
)

require (
	github.com/mrz1836/go-whatsonchain v1.3.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
)

// go-sdk with b017-native's interpreter fix (third_party/go-sdk-patches), until it is merged upstream.
// third_party/setup.sh fetches it. A module that imports this one needs the same replace: Go does not
// carry replace directives over to dependents.
replace github.com/bsv-blockchain/go-sdk => ../third_party/go-sdk
