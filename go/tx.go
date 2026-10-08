package b017

// tx.go - the transaction model of the reference (@bsv/sdk 2.8.11 `Transaction`, src/transaction/Transaction.ts),
// as far as b017 relies on it. A TS input may carry a source txid, an attached source transaction, or both, and
// may lack an unlocking script; the scanner's verdicts depend on which. go-sdk's Transaction cannot hold those
// states, so the port keeps its own model and converts to go-sdk only to run the script interpreter, parse BEEF
// and compute merkle roots (convert.go).

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// Input is a TS TransactionInput.
type Input struct {
	// SourceTXID is the display-order txid hex the input spends; "" is TS `undefined`.
	SourceTXID        string
	SourceOutputIndex uint32
	// SourceTransaction is the attached source tx, if any.
	SourceTransaction *Transaction
	// UnlockingScript is nil when the input has none (TS `undefined`).
	UnlockingScript *Script
	// Sequence is the nSequence; nil is TS `undefined` (serialised and executed as 0xffffffff).
	Sequence *uint32
	// Template is the TS `unlockingScriptTemplate`: Sign fills UnlockingScript from it.
	Template UnlockTemplate
}

// Output is a TS TransactionOutput.
type Output struct {
	// Satoshis is nil when the amount is undefined (TS); serialised as 0.
	Satoshis      *uint64
	LockingScript *Script
	// Change is the TS `change` flag: Fee0 computes its amount.
	Change bool
}

// Transaction is a TS Transaction.
type Transaction struct {
	Version    uint32
	Inputs     []*Input
	Outputs    []*Output
	LockTime   uint32
	MerklePath *MerklePath
}

// U64 and U32 return pointers for the optional fields.
func U64(v uint64) *uint64 { return &v }
func U32(v uint32) *uint32 { return &v }

// Sats is `satoshis ?? 0`.
func (o *Output) Sats() uint64 {
	if o == nil || o.Satoshis == nil {
		return 0
	}
	return *o.Satoshis
}

// Seq is `sequence ?? 0xffffffff`.
func (i *Input) Seq() uint32 {
	if i.Sequence == nil {
		return 0xffffffff
	}
	return *i.Sequence
}

// SourceOutput is `input.sourceTransaction?.outputs[input.sourceOutputIndex]` (nil when absent or out of range).
func (i *Input) SourceOutput() *Output {
	if i == nil || i.SourceTransaction == nil || int(i.SourceOutputIndex) >= len(i.SourceTransaction.Outputs) {
		return nil
	}
	return i.SourceTransaction.Outputs[i.SourceOutputIndex]
}

// ToBinary is TS `toBinary` (the raw serialisation; throws in TS where an error is returned here).
func (t *Transaction) ToBinary() ([]byte, error) {
	w := &writer{}
	w.u32(t.Version)
	w.varint(uint64(len(t.Inputs)))
	for _, in := range t.Inputs {
		if in.SourceTXID == "" {
			if in.SourceTransaction == nil {
				return nil, errors.New("sourceTransaction is undefined")
			}
			h, err := in.SourceTransaction.Hash()
			if err != nil {
				return nil, err
			}
			w.bytes(h)
		} else {
			id, err := requireTXID(in.SourceTXID)
			if err != nil {
				return nil, err
			}
			w.bytes(reverse(id))
		}
		w.u32(in.SourceOutputIndex)
		if in.UnlockingScript == nil {
			return nil, errors.New("unlockingScript is undefined")
		}
		b := in.UnlockingScript.ToBinary()
		w.varint(uint64(len(b)))
		w.bytes(b)
		w.u32(in.Seq())
	}
	w.varint(uint64(len(t.Outputs)))
	for _, o := range t.Outputs {
		w.u64(o.Sats())
		if o.LockingScript == nil {
			return nil, errors.New("Cannot read properties of undefined (reading 'toUint8Array')")
		}
		b := o.LockingScript.ToBinary()
		w.varint(uint64(len(b)))
		w.bytes(b)
	}
	w.u32(t.LockTime)
	return w.b, nil
}

// Hash is TS `hash()`: sha256d of the serialisation (internal byte order).
func (t *Transaction) Hash() ([]byte, error) {
	b, err := t.ToBinary()
	if err != nil {
		return nil, err
	}
	return sha256d(b), nil
}

// ID is TS `id('hex')`: the display-order txid.
func (t *Transaction) ID() (string, error) {
	h, err := t.Hash()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(reverse(h)), nil
}

// MustID is ID for transactions known to serialise; it panics otherwise (the scanner recovers panics into
// `unverifiable input: …`, as the TS scanner catches the throw).
func (t *Transaction) MustID() string {
	id, err := t.ID()
	if err != nil {
		panic(err)
	}
	return id
}

// MustHash is Hash, panicking like MustID.
func (t *Transaction) MustHash() []byte {
	h, err := t.Hash()
	if err != nil {
		panic(err)
	}
	return h
}

// ToHex is TS `toHex`.
func (t *Transaction) ToHex() (string, error) {
	b, err := t.ToBinary()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// TransactionFromBinary is TS `Transaction.fromBinary` (strict varints, no trailing data).
func TransactionFromBinary(b []byte) (*Transaction, error) {
	r := &reader{b: b}
	t, err := readTransaction(r)
	if err != nil {
		return nil, err
	}
	if !r.eof() {
		return nil, errors.New("Serialized transaction contains trailing data")
	}
	return t, nil
}

// TransactionFromHex is TS `Transaction.fromHex`.
func TransactionFromHex(h string) (*Transaction, error) {
	b, err := hexToBytes(h)
	if err != nil {
		return nil, err
	}
	return TransactionFromBinary(b)
}

func readTransaction(r *reader) (*Transaction, error) {
	t := &Transaction{}
	var err error
	if t.Version, err = r.u32(); err != nil {
		return nil, err
	}
	n, err := r.varintStrict()
	if err != nil {
		return nil, err
	}
	for i := uint64(0); i < n; i++ {
		id, err := r.read(32)
		if err != nil {
			return nil, err
		}
		vout, err := r.u32()
		if err != nil {
			return nil, err
		}
		sl, err := r.varintStrict()
		if err != nil {
			return nil, err
		}
		sb, err := r.read(int(sl))
		if err != nil {
			return nil, err
		}
		seq, err := r.u32()
		if err != nil {
			return nil, err
		}
		t.Inputs = append(t.Inputs, &Input{
			SourceTXID: hex.EncodeToString(reverse(id)), SourceOutputIndex: vout,
			UnlockingScript: ScriptFromBinary(sb), Sequence: U32(seq),
		})
	}
	n, err = r.varintStrict()
	if err != nil {
		return nil, err
	}
	for i := uint64(0); i < n; i++ {
		sat, err := r.u64()
		if err != nil {
			return nil, err
		}
		sl, err := r.varintStrict()
		if err != nil {
			return nil, err
		}
		sb, err := r.read(int(sl))
		if err != nil {
			return nil, err
		}
		t.Outputs = append(t.Outputs, &Output{Satoshis: U64(sat), LockingScript: ScriptFromBinary(sb)})
	}
	if t.LockTime, err = r.u32(); err != nil {
		return nil, err
	}
	return t, nil
}

func requireTXID(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("sourceTXID must be a 64-character hexadecimal string")
	}
	return b, nil
}

func hexToBytes(h string) ([]byte, error) {
	if len(h)%2 != 0 {
		return nil, errors.New("Invalid hex string")
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, errors.New("Invalid hex string")
	}
	return b, nil
}

func sha256d(b []byte) []byte {
	h := sha256.Sum256(b)
	h2 := sha256.Sum256(h[:])
	return h2[:]
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

// ---- byte writer / reader (TS Utils.Writer / Reader) ----

type writer struct{ b []byte }

func (w *writer) bytes(b []byte) { w.b = append(w.b, b...) }
func (w *writer) u32(v uint32)   { w.b = binary.LittleEndian.AppendUint32(w.b, v) }
func (w *writer) u64(v uint64)   { w.b = binary.LittleEndian.AppendUint64(w.b, v) }
func (w *writer) varint(n uint64) { w.b = append(w.b, varintBytes(n)...) }

// varintBytes is TS `writeVarIntNum`.
func varintBytes(n uint64) []byte {
	switch {
	case n < 0xfd:
		return []byte{byte(n)}
	case n <= 0xffff:
		return []byte{0xfd, byte(n), byte(n >> 8)}
	case n <= 0xffffffff:
		b := []byte{0xfe, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(b[1:], uint32(n))
		return b
	default:
		b := make([]byte, 9)
		b[0] = 0xff
		binary.LittleEndian.PutUint64(b[1:], n)
		return b
	}
}

type reader struct {
	b   []byte
	pos int
}

var errEOF = errors.New("Reader: not enough data")

func (r *reader) eof() bool { return r.pos >= len(r.b) }
func (r *reader) read(n int) ([]byte, error) {
	if n < 0 || r.pos+n > len(r.b) {
		return nil, errEOF
	}
	out := clone(r.b[r.pos : r.pos+n])
	r.pos += n
	return out, nil
}
func (r *reader) u8() (byte, error) {
	b, err := r.read(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}
func (r *reader) u16() (uint16, error) {
	b, err := r.read(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}
func (r *reader) u32() (uint32, error) {
	b, err := r.read(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}
func (r *reader) u64() (uint64, error) {
	b, err := r.read(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

// varintStrict is TS `readVarIntNumStrict(false)`: a canonical varint.
func (r *reader) varintStrict() (uint64, error) {
	first, err := r.u8()
	if err != nil {
		return 0, err
	}
	switch first {
	case 0xfd:
		v, err := r.u16()
		if err != nil {
			return 0, err
		}
		if v < 0xfd {
			return 0, errors.New("Non-canonical varint")
		}
		return uint64(v), nil
	case 0xfe:
		v, err := r.u32()
		if err != nil {
			return 0, err
		}
		if v <= 0xffff {
			return 0, errors.New("Non-canonical varint")
		}
		return uint64(v), nil
	case 0xff:
		v, err := r.u64()
		if err != nil {
			return 0, err
		}
		if v <= 0xffffffff {
			return 0, errors.New("Non-canonical varint")
		}
		return v, nil
	default:
		return uint64(first), nil
	}
}
