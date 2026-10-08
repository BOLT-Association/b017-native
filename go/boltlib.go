package b017

// boltlib.go - src/lib/boltLib.ts: the layout-agnostic helpers shared by both token streams.

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

func errorf(format string, a ...any) error { return fmt.Errorf(format, a...) }

// UnlockTemplate is the TS ScriptTemplate unlocker: `{ sign(tx, inputIndex), estimateLength() }`.
type UnlockTemplate interface {
	Sign(ctx context.Context, tx *Transaction, inputIndex int) (*Script, error)
	EstimateLength() int
}

// BuildOutpoint is `buildOutpoint`: tx hash (internal order) + LE32 vout.
func BuildOutpoint(tx *Transaction, outputIndex uint32) []byte {
	return append(tx.MustHash(), le32(outputIndex)...)
}

// BuildChangeOutput is `buildChangeOutput`: 8-byte value + varint script length + script, or [] when absent.
func BuildChangeOutput(tx *Transaction, outputIndex int) []byte {
	if outputIndex < 0 || outputIndex >= len(tx.Outputs) || tx.Outputs[outputIndex] == nil {
		return []byte{}
	}
	o := tx.Outputs[outputIndex]
	w := &writer{}
	w.u64(o.Sats())
	b := o.LockingScript.ToBinary()
	w.varint(uint64(len(b)))
	w.bytes(b)
	return w.b
}

// CreateSignature is `createSignature`: the signer signs sha256(preimage) (the engine double-hashes), returning
// the checksig-format signature and the signer's public key.
func CreateSignature(ctx context.Context, signer Signer, preimage []byte, scope uint32) (sigForScript, pubkeyForScript []byte, err error) {
	raw, err := signer.Sign(ctx, Sha256(preimage))
	if err != nil {
		return nil, nil, err
	}
	return raw.ChecksigFormat(scope), signer.PublicKey(), nil
}

type p2pkhUnlocker struct{ signer Signer }

// P2PKHUnlock is boltLib `p2pkhUnlock`: a P2PKH unlock driven by a Signer.
func P2PKHUnlock(signer Signer) UnlockTemplate { return p2pkhUnlocker{signer} }

func (u p2pkhUnlocker) EstimateLength() int { return 108 }
func (u p2pkhUnlocker) Sign(ctx context.Context, tx *Transaction, inputIndex int) (*Script, error) {
	input := tx.Inputs[inputIndex]
	src := input.SourceOutput()
	sourceTXID := input.SourceTXID
	if sourceTXID == "" && input.SourceTransaction != nil {
		id, err := input.SourceTransaction.ID()
		if err != nil {
			return nil, err
		}
		sourceTXID = id
	}
	if sourceTXID == "" || src == nil {
		return nil, errors.New("p2pkhUnlock requires the input's source transaction")
	}
	pre, err := FormatPreimage(PreimageParams{
		SourceTXID: sourceTXID, SourceOutputIndex: input.SourceOutputIndex, SourceSatoshis: src.Sats(),
		TransactionVersion: tx.Version, OtherInputs: RefsOf(tx.Inputs, inputIndex), InputIndex: inputIndex,
		Outputs: tx.Outputs, InputSequence: input.Sequence, Subscript: src.LockingScript, LockTime: tx.LockTime,
		Scope: SignatureScope,
	})
	if err != nil {
		return nil, err
	}
	sig, pub, err := CreateSignature(ctx, u.signer, pre, SignatureScope)
	if err != nil {
		return nil, err
	}
	return NewScript([]Chunk{{Op: byte(len(sig)), Data: sig}, {Op: byte(len(pub)), Data: pub}}), nil
}

// Ctx is splitCtx's result: a BIP143 preimage split around its scriptCode.
type Ctx struct {
	Header, CodeLen, UnlockScriptCode, LockScriptCode, Footer, LockLen []byte
}

// SplitCtx is `splitCtx`: header(104) + scriptCodeLen + unlockScriptCode(unlockBytesLen) + lockScriptCode +
// footer(52) + varint(len lockScriptCode).
func SplitCtx(ctx []byte, unlockBytesLen int) Ctx {
	sl := func(a, b int) []byte { // JS slice: clamped, never panics
		if a > len(ctx) {
			a = len(ctx)
		}
		if b > len(ctx) {
			b = len(ctx)
		}
		if b < a {
			b = a
		}
		return clone(ctx[a:b])
	}
	header := sl(0, 104)
	first := 0
	if len(ctx) > 104 {
		first = int(ctx[104])
	}
	lenSize := 1
	switch first {
	case 0xfd:
		lenSize = 3
	case 0xfe:
		lenSize = 5
	case 0xff:
		lenSize = 9
	}
	codeLen := sl(104, 104+lenSize)
	offset := 104 + lenSize
	actual := first
	at := sl(105, 105+8)
	switch first {
	case 0xfd:
		if len(at) >= 2 {
			actual = int(binary.LittleEndian.Uint16(at))
		}
	case 0xfe:
		if len(at) >= 4 {
			actual = int(binary.LittleEndian.Uint32(at))
		}
	case 0xff:
		if len(at) >= 8 {
			actual = int(binary.LittleEndian.Uint64(at))
		}
	}
	code := sl(offset, offset+actual)
	offset += actual
	n := unlockBytesLen
	if n > len(code) {
		n = len(code)
	}
	unlock := clone(code[:n])
	lock := clone(code[n:])
	footer := sl(offset, offset+52)
	return Ctx{Header: header, CodeLen: codeLen, UnlockScriptCode: unlock, LockScriptCode: lock, Footer: footer,
		LockLen: varintBytes(uint64(len(lock)))}
}

func le32(n uint32) []byte { return binary.LittleEndian.AppendUint32(nil, n) }
func le64(n uint64) []byte { return binary.LittleEndian.AppendUint64(nil, n) }

// TxVersion / TxLockTime are `txVersion` / `txLockTime` (4-byte LE).
func TxVersion(tx *Transaction) []byte  { return le32(tx.Version) }
func TxLockTime(tx *Transaction) []byte { return le32(tx.LockTime) }

// SpentOutpoint is `spentOutpoint`: the 36-byte outpoint input `vin` spends (attached source's hash, else the
// reversed sourceTXID), or [].
func SpentOutpoint(tx *Transaction, vin int) []byte {
	if vin < 0 || vin >= len(tx.Inputs) {
		return []byte{}
	}
	in := tx.Inputs[vin]
	var txid []byte
	if in.SourceTransaction != nil {
		txid = in.SourceTransaction.MustHash()
	} else {
		b, err := hex.DecodeString(in.SourceTXID)
		if err != nil {
			b = jsHexToArray(in.SourceTXID)
		}
		txid = reverse(b)
	}
	if len(txid) == 0 {
		return []byte{}
	}
	return append(clone(txid), le32(in.SourceOutputIndex)...)
}

// jsHexToArray is Utils.toArray(str, 'hex') for a malformed string: pairs parsed with parseInt, NaN -> 0.
func jsHexToArray(s string) []byte {
	if len(s)%2 != 0 {
		s = "0" + s
	}
	out := make([]byte, 0, len(s)/2)
	for i := 0; i+1 < len(s); i += 2 {
		var v byte
		if b, err := hex.DecodeString(s[i : i+2]); err == nil {
			v = b[0]
		}
		out = append(out, v)
	}
	return out
}

// VinChunk is `vinChunk`: data of input vin's unlocking chunk, or [].
func VinChunk(tx *Transaction, vin, chunkIdx int) []byte {
	if vin < 0 || vin >= len(tx.Inputs) || tx.Inputs[vin].UnlockingScript == nil {
		return []byte{}
	}
	return clone(ChunkData(tx.Inputs[vin].UnlockingScript, chunkIdx))
}

// VinSequence is `vinSequence`: input vin's LE32 nSequence, or [].
func VinSequence(tx *Transaction, vin int) []byte {
	if vin < 0 || vin >= len(tx.Inputs) {
		return []byte{}
	}
	return le32(tx.Inputs[vin].Seq())
}

// VinScript is `vinScript`: input vin's unlocking script bytes, or [].
func VinScript(tx *Transaction, vin int) []byte {
	if vin < 0 || vin >= len(tx.Inputs) || tx.Inputs[vin].UnlockingScript == nil {
		return []byte{}
	}
	return tx.Inputs[vin].UnlockingScript.ToBinary()
}

// VoutChunk is `voutChunk`: data of output vout's locking chunk, or [] (TS throws for a missing output).
func VoutChunk(tx *Transaction, vout, chunkIdx int) []byte {
	return clone(ChunkData(tx.Outputs[vout].LockingScript, chunkIdx))
}

// OutputValue is `outputValue`: output idx's LE64 value, or [].
func OutputValue(tx *Transaction, idx int) []byte {
	if idx < 0 || idx >= len(tx.Outputs) {
		return []byte{}
	}
	return le64(tx.Outputs[idx].Sats())
}

// OutputScript is `outputScript`: output idx's locking script bytes, or [].
func OutputScript(tx *Transaction, idx int) []byte {
	if idx < 0 || idx >= len(tx.Outputs) {
		return []byte{}
	}
	return tx.Outputs[idx].LockingScript.ToBinary()
}
