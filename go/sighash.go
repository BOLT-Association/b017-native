package b017

// sighash.go - TransactionSignature.format (BIP143 with FORKID, @bsv/sdk 2.8.11 formatBip143), the signature
// encodings, hashes, and the Signer abstraction of boltLib (async-signer branch).

import (
	"context"
	"crypto/sha256"
	"errors"
	"math/big"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // hash160 is sha256 + ripemd160 by definition
)

// Sighash flags (TransactionSignature.SIGHASH_*).
const (
	SighashAll          = 0x01
	SighashNone         = 0x02
	SighashSingle       = 0x03
	SighashForkID       = 0x40
	SighashAnyoneCanPay = 0x80
)

// SignatureScope is SIGHASH_FORKID | SIGHASH_ALL, the only scope b017 signs with.
const SignatureScope = SighashForkID | SighashAll

// OutpointRef is an input as the preimage sees it: what it spends and its sequence.
type OutpointRef struct {
	SourceTXID        string
	SourceTransaction *Transaction
	SourceOutputIndex uint32
	Sequence          *uint32
}

// PreimageParams are the TransactionSignature.format parameters.
type PreimageParams struct {
	SourceTXID         string
	SourceOutputIndex  uint32
	SourceSatoshis     uint64
	TransactionVersion uint32
	OtherInputs        []OutpointRef
	InputIndex         int
	Outputs            []*Output
	InputSequence      *uint32
	Subscript          *Script
	LockTime           uint32
	Scope              uint32
}

// RefsOf turns a tx's inputs (except `skip`, -1 for none) into OutpointRefs, as `tx.inputs.filter(...)` does.
func RefsOf(inputs []*Input, skip int) []OutpointRef {
	out := []OutpointRef{}
	for k, in := range inputs {
		if k == skip {
			continue
		}
		out = append(out, OutpointRef{SourceTXID: in.SourceTXID, SourceTransaction: in.SourceTransaction,
			SourceOutputIndex: in.SourceOutputIndex, Sequence: in.Sequence})
	}
	return out
}

func seqOr(s *uint32) uint32 {
	if s == nil {
		return 0xffffffff
	}
	return *s
}

// FormatPreimage is TransactionSignature.format for a FORKID scope (BIP143).
func FormatPreimage(p PreimageParams) ([]byte, error) {
	cur := OutpointRef{SourceTXID: p.SourceTXID, SourceOutputIndex: p.SourceOutputIndex, Sequence: p.InputSequence}
	inputs := append([]OutpointRef{}, p.OtherInputs...)
	if p.InputIndex > len(inputs) {
		return nil, errors.New("inputIndex out of range")
	}
	inputs = append(inputs[:p.InputIndex], append([]OutpointRef{cur}, inputs[p.InputIndex:]...)...)
	base := p.Scope & 31
	zero := make([]byte, 32)

	hashPrevouts := zero
	if p.Scope&SighashAnyoneCanPay == 0 {
		w := &writer{}
		for _, in := range inputs {
			if in.SourceTXID == "" {
				if in.SourceTransaction == nil {
					return nil, errors.New("Missing sourceTransaction for input")
				}
				h, err := in.SourceTransaction.Hash()
				if err != nil {
					return nil, err
				}
				w.bytes(h)
			} else {
				id, err := hexToBytes(in.SourceTXID)
				if err != nil {
					return nil, err
				}
				w.bytes(reverse(id))
			}
			w.u32(in.SourceOutputIndex)
		}
		hashPrevouts = sha256d(w.b)
	}
	hashSequence := zero
	if p.Scope&SighashAnyoneCanPay == 0 && base != SighashSingle && base != SighashNone {
		w := &writer{}
		for _, in := range inputs {
			w.u32(seqOr(in.Sequence))
		}
		hashSequence = sha256d(w.b)
	}
	writeOut := func(w *writer, o *Output) {
		w.u64(o.Sats())
		var s []byte
		if o.LockingScript != nil {
			s = o.LockingScript.ToBinary()
		}
		w.varint(uint64(len(s)))
		w.bytes(s)
	}
	var hashOutputs []byte
	switch {
	case base != SighashSingle && base != SighashNone:
		w := &writer{}
		for _, o := range p.Outputs {
			writeOut(w, o)
		}
		hashOutputs = sha256d(w.b)
	case base == SighashSingle && p.InputIndex < len(p.Outputs):
		w := &writer{}
		writeOut(w, p.Outputs[p.InputIndex])
		hashOutputs = sha256d(w.b)
	default:
		hashOutputs = zero
	}

	w := &writer{}
	w.u32(p.TransactionVersion)
	w.bytes(hashPrevouts)
	w.bytes(hashSequence)
	id, err := hexToBytes(p.SourceTXID)
	if err != nil {
		return nil, err
	}
	w.bytes(reverse(id))
	w.u32(p.SourceOutputIndex)
	sub := p.Subscript.ToBinary()
	w.varint(uint64(len(sub)))
	w.bytes(sub)
	w.u64(p.SourceSatoshis)
	w.u32(seqOr(p.InputSequence))
	w.bytes(hashOutputs)
	w.u32(p.LockTime)
	w.u32(p.Scope)
	return w.b, nil
}

// Sha256 and Hash160 are Hash.sha256 / Hash.hash160.
func Sha256(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func Hash160(b []byte) []byte {
	r := ripemd160.New()
	r.Write(Sha256(b))
	return r.Sum(nil)
}

// Signature is an ECDSA (r, s) pair, as a Signer returns it (not normalised: TS keeps what the signer gave).
type Signature struct{ R, S *big.Int }

// DER is TS Signature.toDER: canonical integers, S as given.
func (s Signature) DER() []byte {
	enc := func(n *big.Int) []byte {
		b := n.Bytes()
		if len(b) == 0 {
			b = []byte{0}
		}
		if b[0]&0x80 != 0 {
			b = append([]byte{0}, b...)
		}
		return b
	}
	r, sb := enc(s.R), enc(s.S)
	out := []byte{0x30, byte(4 + len(r) + len(sb)), 0x02, byte(len(r))}
	out = append(out, r...)
	out = append(out, 0x02, byte(len(sb)))
	return append(out, sb...)
}

// ChecksigFormat is TransactionSignature.toChecksigFormat: DER + the scope byte.
func (s Signature) ChecksigFormat(scope uint32) []byte { return append(s.DER(), byte(scope)) }

// Signer is boltLib's Signer: a compressed public key and a signature over sha256(msg) (what PrivateKey.sign
// does). It may block (a wallet over IPC); ctx bounds it.
type Signer interface {
	PublicKey() []byte
	Sign(ctx context.Context, msg []byte) (Signature, error)
}

// KeySigner is a PrivateKey as a Signer (TS `toSigner(privateKey)`).
type KeySigner struct{ Key *ec.PrivateKey }

func (k KeySigner) PublicKey() []byte { return k.Key.PubKey().Compressed() }
func (k KeySigner) Sign(_ context.Context, msg []byte) (Signature, error) {
	sig, err := k.Key.Sign(Sha256(msg))
	if err != nil {
		return Signature{}, err
	}
	return Signature{R: sig.R, S: sig.S}, nil
}

// Recipient is boltLib's Recipient: a Signer the caller controls (so a builder can continue as the new owner), or
// a third party's 33-byte compressed public key ([]byte or PubKeyRecipient).
type Recipient any

// PubKeyRecipient is a recipient known only by its public key.
type PubKeyRecipient []byte

// RecipientPubKey is boltLib `recipientPubKey`.
func RecipientPubKey(r Recipient) []byte {
	switch v := r.(type) {
	case Signer:
		return v.PublicKey()
	case PubKeyRecipient:
		return []byte(v)
	case []byte:
		return v
	}
	panic(errorf("not a recipient: %T", r))
}

// RecipientSigner is boltLib `recipientSigner`: the Signer, or nil for a public-key-only recipient.
func RecipientSigner(r Recipient) Signer {
	if s, ok := r.(Signer); ok {
		return s
	}
	return nil
}
