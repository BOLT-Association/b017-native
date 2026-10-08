package b017

// pay2proof.go - src/tokens/templates/pay2Proof.ts: the "b017 marker" proof output.

import (
	"context"
	"errors"
)

// Pay2ProofLock is Pay2ProofTemplate.lock: `b017 OP_EQUALVERIFY OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG`.
func Pay2ProofLock(pubKeyHash []byte) *Script {
	return NewScript([]Chunk{
		{Op: 2, Data: []byte{0xb0, 0x17}},
		{Op: OP_EQUALVERIFY},
		{Op: OP_DUP},
		{Op: OP_HASH160},
		{Op: byte(len(pubKeyHash)), Data: clone(pubKeyHash)},
		{Op: OP_EQUALVERIFY},
		{Op: OP_CHECKSIG},
	})
}

// Pay2ProofUnlocker is Pay2ProofTemplate.unlock. SourceSatoshis / LockingScript are the optional overrides
// (0 / nil = take them from the attached source; as in TS, a 0 amount counts as missing).
type Pay2ProofUnlocker struct {
	Signer         Signer
	SourceSatoshis uint64
	LockingScript  *Script
}

// Pay2ProofUnlock is `new Pay2ProofTemplate().unlock(privKey, sourceSatoshis?, lockingScript?)`.
func Pay2ProofUnlock(s Signer, sourceSatoshis uint64, lockingScript *Script) *Pay2ProofUnlocker {
	return &Pay2ProofUnlocker{Signer: s, SourceSatoshis: sourceSatoshis, LockingScript: lockingScript}
}

func (u *Pay2ProofUnlocker) EstimateLength() int { return 111 }

func (u *Pay2ProofUnlocker) Sign(ctx context.Context, tx *Transaction, inputIndex int) (*Script, error) {
	input := tx.Inputs[inputIndex]
	sourceTXID := input.SourceTXID
	if sourceTXID == "" && input.SourceTransaction != nil {
		id, err := input.SourceTransaction.ID()
		if err != nil {
			return nil, err
		}
		sourceTXID = id
	}
	if sourceTXID == "" {
		return nil, errors.New("The input sourceTXID or sourceTransaction is required for transaction signing.")
	}
	// `sourceSatoshis ||= …` and `lockingScript ||= …` assign the closure's variables: later sign() calls keep them.
	if u.SourceSatoshis == 0 {
		if o := input.SourceOutput(); o != nil {
			u.SourceSatoshis = o.Sats()
		}
	}
	if u.SourceSatoshis == 0 {
		return nil, errors.New("The sourceSatoshis or input sourceTransaction is required for transaction signing.")
	}
	if u.LockingScript == nil {
		if o := input.SourceOutput(); o != nil {
			u.LockingScript = o.LockingScript
		}
	}
	if u.LockingScript == nil {
		return nil, errors.New("The lockingScript or input sourceTransaction is required for transaction signing.")
	}
	pre, err := FormatPreimage(PreimageParams{
		SourceTXID: sourceTXID, SourceOutputIndex: input.SourceOutputIndex, SourceSatoshis: u.SourceSatoshis,
		TransactionVersion: tx.Version, OtherInputs: RefsOf(tx.Inputs, inputIndex), InputIndex: inputIndex,
		Outputs: tx.Outputs, InputSequence: input.Sequence, Subscript: u.LockingScript, LockTime: tx.LockTime,
		Scope: SignatureScope,
	})
	if err != nil {
		return nil, err
	}
	sig, pub, err := CreateSignature(ctx, u.Signer, pre, SignatureScope)
	if err != nil {
		return nil, err
	}
	return NewScript([]Chunk{
		{Op: byte(len(sig)), Data: sig},
		{Op: byte(len(pub)), Data: pub},
		{Op: 2, Data: []byte{0xb0, 0x17}},
	}), nil
}
