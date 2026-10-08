package b017

// fingerprints.go - src/lib/scanner/fingerprints.ts: per-type recognition of BOLT token locks (leading push
// layout + sha256 of the static suffix) and the golden p2Proof fingerprint.

import "encoding/hex"

// TokenType is the reference's TokenType.
type TokenType string

const (
	TokenMinSimpleBOLT   TokenType = "MinSimpleBOLT"
	TokenAuthBOLT        TokenType = "AuthBOLT"
	TokenSimpleMultiBOLT TokenType = "SimpleMultiBOLT"
)

// TypeSpec is a REGISTRY entry.
type TypeSpec struct {
	Type          TokenType
	DataPushCount int
	PushLengths   []int
	SuffixHashHex string
}

// registryOrder is Object.values(REGISTRY) order (the LAYOUTS key order), which recognizeType walks.
var registryOrder = []TokenType{TokenMinSimpleBOLT, TokenAuthBOLT, TokenSimpleMultiBOLT}

// Sha256Hex is `sha256Hex`.
func Sha256Hex(b []byte) string { return hex.EncodeToString(Sha256(b)) }

// REGISTRY is the reference's REGISTRY, with each suffix hash computed from the embedded suffix.
var REGISTRY = func() map[TokenType]TypeSpec {
	layouts := map[TokenType][]int{
		TokenMinSimpleBOLT:   {20, 20, 1, 36, 36, 33},
		TokenAuthBOLT:        {20, 20, 1, 36, 36, 33},
		TokenSimpleMultiBOLT: {16, 16, 20, 20, 20, 36, 1, 1, 36, 36, 33},
	}
	suffix := map[TokenType]string{TokenMinSimpleBOLT: MinSimpleLockSuffixHex, TokenAuthBOLT: AuthBoltLockSuffixHex, TokenSimpleMultiBOLT: SimpleMultiLockSuffixHex}
	out := map[TokenType]TypeSpec{}
	for _, t := range registryOrder {
		b, _ := hex.DecodeString(suffix[t])
		out[t] = TypeSpec{Type: t, DataPushCount: len(layouts[t]), PushLengths: layouts[t], SuffixHashHex: Sha256Hex(b)}
	}
	return out
}()

// RecognizeType is `recognizeType`: the type whose push layout AND suffix hash the lock matches, or "".
// `expected` "" means any type.
func RecognizeType(lock *Script, expected TokenType) TokenType {
	if lock == nil {
		return ""
	}
	chunks := lock.Chunks()
	for _, t := range registryOrder {
		spec := REGISTRY[t]
		if expected != "" && spec.Type != expected {
			continue
		}
		n := spec.DataPushCount
		if len(chunks) <= n {
			continue
		}
		ok := true
		for i := 0; i < n; i++ {
			if len(chunks[i].Data) != spec.PushLengths[i] {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		suffix := NewScript(append([]Chunk{}, chunks[n:]...))
		if Sha256Hex(suffix.ToBinary()) != spec.SuffixHashHex {
			continue
		}
		return spec.Type
	}
	return ""
}

// IssuerPubKeyOf is `issuerPubKeyOf`: the last dynamic push of a recognised token, or [].
func IssuerPubKeyOf(lock *Script, t TokenType) []byte {
	return clone(ChunkData(lock, REGISTRY[t].DataPushCount-1))
}

const p2pPkhIdx = 4

var p2pRef = Pay2ProofLock(make([]byte, 20))
var p2pLen = len(p2pRef.Chunks())

func p2pSkeleton(lock *Script) []byte {
	chunks := lock.Chunks()
	out := make([]Chunk, len(chunks))
	for i, c := range chunks {
		if i == p2pPkhIdx {
			out[i] = Chunk{Op: c.Op, Data: make([]byte, len(c.Data))}
		} else {
			out[i] = c
		}
	}
	return NewScript(out).ToBinary()
}

var p2pSkeletonHash = Sha256Hex(p2pSkeleton(p2pRef))

// RecognizeP2P is `recognizeP2P`: a genuine p2Proof lock (static skeleton hash + a 20-byte pkh at chunk 4).
func RecognizeP2P(lock *Script) bool {
	if lock == nil || len(lock.Chunks()) != p2pLen {
		return false
	}
	pkh := lock.Chunks()[p2pPkhIdx].Data
	if pkh == nil || len(pkh) != 20 {
		return false
	}
	return Sha256Hex(p2pSkeleton(lock)) == p2pSkeletonHash
}
