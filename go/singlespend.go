package b017

// singlespend.go - src/lib/single/singleSpend.ts: the shared unlock assembler of the NFT-family templates
// (MinSimpleBolt, AuthBolt): transfer commit/settle, back-reaching settle, zero-funding, melt.

import (
	"context"
	"errors"
)

// SingleAncestorArgCount is SINGLE_ANCESTOR_ARG_COUNT.
const SingleAncestorArgCount = 26

func isProofLock(s *Script) bool {
	if s == nil {
		return false
	}
	c := s.Chunks()
	if len(c) == 0 {
		return false
	}
	d := c[0].Data
	return d != nil && len(d) == 2 && d[0] == 0xb0 && d[1] == 0x17
}

// EmptySingleAncestorChunks is `emptySingleAncestorChunks(count)`: count OP_0 pushes.
func EmptySingleAncestorChunks(count int) []Chunk {
	out := []Chunk{}
	for i := 0; i < count; i++ {
		out = append(out, ChunksFromBin(nil)...)
	}
	return out
}

// SingleUnlockParams are singleSpendUnlock's parameters. SourceSatoshis / LockingScript nil = take them from the
// input's attached source (TS `??`). Layout nil = MinSimpleLayout.
type SingleUnlockParams struct {
	Signer                Signer
	BeneficiaryPubKeyHash []byte
	UnlockSuffix          *Script
	ForceNoChange         bool
	ForceNoFund           bool
	PrevTxs               []*Transaction
	SourceSatoshis        *uint64
	LockingScript         *Script
	LeadingValuePushes    int
	Layout                *SingleLayout
	AuthOrMiscData        []byte
	Melt                  bool
}

type singleUnlocker struct{ p SingleUnlockParams }

// SingleSpendUnlock is `singleSpendUnlock`. Requires tx version >= 2.
func SingleSpendUnlock(p SingleUnlockParams) UnlockTemplate { return &singleUnlocker{p} }

func (u *singleUnlocker) EstimateLength() int { return 2000 }

func (u *singleUnlocker) Sign(ctx context.Context, tx *Transaction, inputIndex int) (us *Script, err error) {
	defer func() {
		if r := recover(); r != nil {
			us, err = nil, panicError(r)
		}
	}()
	p := u.p
	layout := MinSimpleLayout
	if p.Layout != nil {
		layout = *p.Layout
	}
	input := tx.Inputs[inputIndex]
	sourceTXID := input.SourceTXID
	if sourceTXID == "" && input.SourceTransaction != nil {
		sourceTXID = input.SourceTransaction.MustID()
	}
	if sourceTXID == "" {
		return nil, errors.New("input sourceTXID or sourceTransaction required for signing")
	}
	var sourceSatoshis *uint64
	if p.SourceSatoshis != nil {
		sourceSatoshis = p.SourceSatoshis
	} else if input.SourceTransaction != nil {
		o := input.SourceTransaction.Outputs[input.SourceOutputIndex]
		if o.Satoshis != nil {
			sourceSatoshis = o.Satoshis
		}
	}
	if sourceSatoshis == nil {
		return nil, errors.New("sourceSatoshis or input sourceTransaction required")
	}
	lockingScript := p.LockingScript
	if lockingScript == nil && input.SourceTransaction != nil {
		lockingScript = input.SourceTransaction.Outputs[input.SourceOutputIndex].LockingScript
	}
	if lockingScript == nil {
		return nil, errors.New("lockingScript or input sourceTransaction required")
	}

	txIdx := len(p.PrevTxs)
	ancestorIdx := txIdx - 3
	hasAncestor := ancestorIdx >= 1 && txIdx >= 4 && txIdx%2 == 0
	var ancestorChunks []Chunk
	if hasAncestor {
		for _, piece := range SingleAncestorPieces(p.PrevTxs[ancestorIdx], p.LeadingValuePushes, layout) {
			ancestorChunks = append(ancestorChunks, ChunksFromBin(piece)...)
		}
	} else {
		ancestorChunks = EmptySingleAncestorChunks(len(layout.PieceNames))
	}

	ocs := NewScript(append(append([]Chunk{}, scriptFromASM("OP_CHECKSIGVERIFY OP_ENDIF").Chunks()...), lockingScript.Chunks()...))
	pre, err := FormatPreimage(PreimageParams{
		SourceTXID: sourceTXID, SourceOutputIndex: input.SourceOutputIndex, SourceSatoshis: *sourceSatoshis,
		TransactionVersion: tx.Version, OtherInputs: RefsOf(tx.Inputs, inputIndex), InputIndex: inputIndex,
		Outputs: tx.Outputs, InputSequence: input.Sequence, Subscript: ocs, LockTime: tx.LockTime, Scope: SignatureScope,
	})
	if err != nil {
		return nil, err
	}
	c, err := SplitCtx(pre, 2)
	if err != nil {
		return nil, err
	}
	ctxForSig := append(append(append(append([]byte{}, c.Header...), c.LockLen...), c.LockScriptCode...), c.Footer...)
	sig, pub, err := CreateSignature(ctx, p.Signer, ctxForSig, SignatureScope)
	if err != nil {
		return nil, err
	}
	suffix := p.UnlockSuffix.Chunks()
	empty := func() []Chunk { return ChunksFromBin(nil) }

	if p.Melt {
		var out []Chunk
		if layout.HasAuth {
			out = append(out, empty()...)
		}
		out = append(out, EmptySingleAncestorChunks(len(layout.PieceNames))...)
		out = append(out, empty()...)
		out = append(out, empty()...)
		out = append(out, empty()...)
		out = append(out, ChunksFromBin(sig)...)
		out = append(out, ChunksFromBin(pub)...)
		for i := 0; i < 6; i++ {
			out = append(out, empty()...)
		}
		out = append(out, suffix...)
		return NewScript(out), nil
	}

	var nextIn *Input
	if inputIndex+1 < len(tx.Inputs) {
		nextIn = tx.Inputs[inputIndex+1]
	}
	var nextLock *Script
	if nextIn != nil {
		if o := nextIn.SourceOutput(); o != nil {
			nextLock = o.LockingScript
		}
	}
	hasProof := false
	if nextIn != nil {
		if nextLock != nil {
			hasProof = isProofLock(nextLock)
		} else {
			hasProof = hasAncestor
		}
	}
	var fundInput *Input
	if !p.ForceNoFund {
		k := inputIndex + 1
		if hasProof {
			k++
		}
		if k < len(tx.Inputs) {
			fundInput = tx.Inputs[k]
		}
	}
	changeIdx := 1
	if len(tx.Outputs) > 1 && isProofLock(tx.Outputs[1].LockingScript) {
		changeIdx = 2
	}
	hasChange := !p.ForceNoChange && len(tx.Outputs) > changeIdx
	if hasChange && fundInput == nil {
		return nil, errors.New("an unfunded spend has no change to return (change needs a funding input)")
	}
	fundOutpoint := []byte{}
	if fundInput != nil {
		if fundInput.SourceTransaction == nil {
			panic(errors.New("Cannot read properties of undefined (reading 'hash')"))
		}
		fundOutpoint = BuildOutpoint(fundInput.SourceTransaction, fundInput.SourceOutputIndex)
	}
	changeOutput := []byte{}
	if hasChange {
		changeOutput = BuildChangeOutput(tx, changeIdx)
	}

	var out []Chunk
	if layout.HasAuth {
		out = append(out, ChunksFromBin(p.AuthOrMiscData)...)
	}
	out = append(out, ancestorChunks...)
	for _, b := range [][]byte{fundOutpoint, changeOutput, p.BeneficiaryPubKeyHash, sig, pub,
		c.Header, c.CodeLen, c.UnlockScriptCode, c.LockScriptCode, c.Footer, c.LockLen} {
		out = append(out, ChunksFromBin(b)...)
	}
	out = append(out, suffix...)
	return NewScript(out), nil
}
