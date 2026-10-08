package b017

// simplemulti.go - src/tokens/templates/SimpleMulti.sx.template.ts: the SimpleMultiBolt fungible contract
// (11 lock data args; 198 unlock args). A nil byte-slice argument is an omitted TS argument (its default applies).

import (
	"context"
	"errors"
)

var (
	simpleMultiLockSuffix   = MustScriptFromHex(SimpleMultiLockSuffixHex)
	simpleMultiUnlockSuffix = MustScriptFromHex(SimpleMultiUnlockSuffixHex)
)

// SimpleMultiTemplate is the SimpleMultiBolt template.
type SimpleMultiTemplate struct{}

// SMBLockArgs are lock()'s arguments after toPubKey and prevTxs.
type SMBLockArgs struct {
	Balance, BalanceCommit, PubKeyHashCommit, PubKeyHashCommit2, OtherGrandparentOutpoint, TxoType, OutputIndexN []byte
	PrevVoutIdx int
}

// Lock is `lock(toPubKey, prevTxs, balance, balanceCommit, pubKeyHashCommit, pubKeyHashCommit2,
// otherGrandparentOutpoint, txoType, outputIndexN, prevVoutIdx)`.
func (SimpleMultiTemplate) Lock(toPubKey []byte, prevTxs []*Transaction, a SMBLockArgs) (s *Script, err error) {
	defer func() {
		if r := recover(); r != nil {
			s, err = nil, panicError(r)
		}
	}()
	isGenesis := len(prevTxs) == 0
	var prevTx *Transaction
	if !isGenesis {
		prevTx = prevTxs[len(prevTxs)-1]
	}
	var prevChunks []Chunk
	if prevTx != nil {
		prevChunks = prevTx.Outputs[a.PrevVoutIdx].LockingScript.Chunks()
	}
	pubKeyHash := Hash160(toPubKey)
	var parent []byte
	if prevTx != nil {
		parent = prevTx.MustHash()
	} else {
		parent = make([]byte, 32)
	}
	parent = append(parent, le32(uint32(a.PrevVoutIdx))...)
	grandparent := make([]byte, 36)
	if prevChunks != nil {
		if prevChunks[8].Data != nil {
			grandparent = clone(prevChunks[8].Data)
		}
	}
	var issuer []byte
	if isGenesis {
		issuer = toPubKey
	} else {
		if prevChunks == nil || prevChunks[10].Data == nil {
			return nil, errors.New("Cannot read properties of undefined (reading 'length')")
		}
		issuer = prevChunks[10].Data
	}
	sc := NewScript(nil)
	for _, b := range [][]byte{
		orDefault(a.Balance, make([]byte, 16)), orDefault(a.BalanceCommit, make([]byte, 16)), pubKeyHash,
		orDefault(a.PubKeyHashCommit, make([]byte, 20)), orDefault(a.PubKeyHashCommit2, make([]byte, 20)),
		orDefault(a.OtherGrandparentOutpoint, make([]byte, 36)), orDefault(a.TxoType, []byte{0x20}),
		orDefault(a.OutputIndexN, []byte{0x00}), parent, grandparent, issuer,
	} {
		sc.WriteBin(b)
	}
	return NewScript(append(append([]Chunk{}, sc.Chunks()...), simpleMultiLockSuffix.Chunks()...)), nil
}

// StaticSuffix is the static contract suffix.
func (SimpleMultiTemplate) StaticSuffix() *Script { return MustScriptFromHex(SimpleMultiLockSuffixHex) }

// SMBUnlockArgs are unlock()'s arguments after the signer, toPubKey and prevTxs.
type SMBUnlockArgs struct {
	ForceNoChange, ForceNoFund                                                       bool
	NextBalanceCommit, NextTxoType, InputIndexN, PubKeyHash2                          []byte
	GrandparentBoltVoutIdx, InteropBoltVoutIdx, InteropPubKeyHash, InteropOutpoint     []byte
	InteropParentOutpoint                                                            []byte
	AncestorTxBRef                                                                   *Transaction
}

type smbUnlocker struct {
	signer   Signer
	toPubKey []byte
	prevTxs  []*Transaction
	a        SMBUnlockArgs
}

// Unlock is `unlock(privateKey, toPubKey, prevTxs, ...)`.
func (SimpleMultiTemplate) Unlock(signer Signer, toPubKey []byte, prevTxs []*Transaction, a SMBUnlockArgs) UnlockTemplate {
	return &smbUnlocker{signer, toPubKey, prevTxs, a}
}

func (u *smbUnlocker) EstimateLength() int { return 2000 }

// extractInputInfo is the template's extractInputInfo (a 0 amount counts as missing, `!sourceSatoshis`).
func extractInputInfo(tx *Transaction, inputIndex int, sats *uint64, lock *Script) (string, uint64, *Script, error) {
	input := tx.Inputs[inputIndex]
	sourceTXID := input.SourceTXID
	if sourceTXID == "" && input.SourceTransaction != nil {
		sourceTXID = input.SourceTransaction.MustID()
	}
	if sourceTXID == "" {
		return "", 0, nil, errors.New("The input sourceTXID or sourceTransaction is required for transaction signing.")
	}
	if sats == nil && input.SourceTransaction != nil {
		sats = input.SourceTransaction.Outputs[input.SourceOutputIndex].Satoshis
	}
	if sats == nil || *sats == 0 {
		return "", 0, nil, errors.New("The sourceSatoshis or input sourceTransaction is required for transaction signing.")
	}
	if lock == nil && input.SourceTransaction != nil {
		lock = input.SourceTransaction.Outputs[input.SourceOutputIndex].LockingScript
	}
	if lock == nil {
		return "", 0, nil, errors.New("The lockingScript or input sourceTransaction is required for transaction signing.")
	}
	return sourceTXID, *sats, lock, nil
}

func buildFundAndChangeOutputs(tx *Transaction, forceNoChange, forceNoFund bool) ([]byte, []byte) {
	fund := []byte{}
	if !forceNoFund {
		in := tx.Inputs[len(tx.Inputs)-1]
		if in.SourceTransaction == nil {
			panic(errors.New("Cannot read properties of undefined (reading 'hash')"))
		}
		fund = BuildOutpoint(in.SourceTransaction, in.SourceOutputIndex)
	}
	change := []byte{}
	if !forceNoChange {
		change = BuildChangeOutput(tx, len(tx.Outputs)-1)
	}
	return fund, change
}

func (u *smbUnlocker) Sign(ctx context.Context, tx *Transaction, inputIndex int) (us *Script, err error) {
	defer func() {
		if r := recover(); r != nil {
			us, err = nil, panicError(r)
		}
	}()
	a := u.a
	sourceTXID, sats, lock, err := extractInputInfo(tx, inputIndex, nil, nil)
	if err != nil {
		return nil, err
	}
	input := tx.Inputs[inputIndex]
	ocs := NewScript(append(append([]Chunk{}, scriptFromASM("OP_CHECKSIGVERIFY OP_ENDIF").Chunks()...), lock.Chunks()...))
	pre, err := FormatPreimage(PreimageParams{
		SourceTXID: sourceTXID, SourceOutputIndex: input.SourceOutputIndex, SourceSatoshis: sats,
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
	sig, pub, err := CreateSignature(ctx, u.signer, ctxForSig, SignatureScope)
	if err != nil {
		return nil, err
	}
	toPubKeyHash := []byte{}
	if len(u.toPubKey) > 0 {
		toPubKeyHash = Hash160(u.toPubKey)
	}
	txIdx := len(u.prevTxs)
	fund, change := buildFundAndChangeOutputs(tx, a.ForceNoChange, a.ForceNoFund)
	ancestorIdx := txIdx - 3
	hasAncestor := ancestorIdx >= 1 && txIdx >= 4 && txIdx%2 == 0
	var ancestorTx *Transaction
	if hasAncestor {
		h, err := u.prevTxs[ancestorIdx].ToHex()
		if err != nil {
			return nil, err
		}
		if ancestorTx, err = TransactionFromHex(h); err != nil {
			return nil, err
		}
	}
	var out []Chunk
	for _, piece := range SMBPieceNames {
		var b []byte
		if ancestorTx != nil {
			b = SMBAncestorPiece(piece, ancestorTx)
		}
		out = append(out, ChunksFromBin(b)...)
	}
	var ancestorB *Transaction
	if a.AncestorTxBRef != nil {
		h, err := a.AncestorTxBRef.ToHex()
		if err != nil {
			return nil, err
		}
		if ancestorB, err = TransactionFromHex(h); err != nil {
			return nil, err
		}
	}
	for _, piece := range SMBPieceNames {
		var b []byte
		if ancestorB != nil {
			b = SMBAncestorPiece(piece, ancestorB)
		}
		out = append(out, ChunksFromBin(b)...)
	}
	for _, b := range [][]byte{
		orDefault(a.GrandparentBoltVoutIdx, []byte{}), orDefault(a.InteropBoltVoutIdx, []byte{}),
		orDefault(a.InteropPubKeyHash, []byte{}), orDefault(a.InteropOutpoint, []byte{}), orDefault(a.InteropParentOutpoint, []byte{}),
		fund, change, toPubKeyHash, orDefault(a.PubKeyHash2, []byte{}),
		orDefault(a.NextBalanceCommit, make([]byte, 16)), orDefault(a.NextTxoType, []byte{0x21}), orDefault(a.InputIndexN, []byte{0x00}),
		sig, pub, c.Header, c.CodeLen, c.UnlockScriptCode, c.LockScriptCode, c.Footer, c.LockLen,
	} {
		out = append(out, ChunksFromBin(b)...)
	}
	out = append(out, simpleMultiUnlockSuffix.Chunks()...)
	return NewScript(out), nil
}

type smbMelter struct {
	signer Signer
	sats   *uint64
	lock   *Script
}

// Melt is `melt(privateKey, sourceSatoshis?, lockingScript?)`.
func (SimpleMultiTemplate) Melt(signer Signer, sourceSatoshis *uint64, lockingScript *Script) UnlockTemplate {
	return &smbMelter{signer, sourceSatoshis, lockingScript}
}

func (m *smbMelter) EstimateLength() int { return 400 }

func (m *smbMelter) Sign(ctx context.Context, tx *Transaction, inputIndex int) (us *Script, err error) {
	defer func() {
		if r := recover(); r != nil {
			us, err = nil, panicError(r)
		}
	}()
	sourceTXID, sats, lock, err := extractInputInfo(tx, inputIndex, m.sats, m.lock)
	if err != nil {
		return nil, err
	}
	input := tx.Inputs[inputIndex]
	pre, err := FormatPreimage(PreimageParams{
		SourceTXID: sourceTXID, SourceOutputIndex: input.SourceOutputIndex, SourceSatoshis: sats,
		TransactionVersion: tx.Version, OtherInputs: RefsOf(tx.Inputs, inputIndex), InputIndex: inputIndex,
		Outputs: tx.Outputs, InputSequence: input.Sequence, Subscript: lock, LockTime: tx.LockTime, Scope: SignatureScope,
	})
	if err != nil {
		return nil, err
	}
	sig, pub, err := CreateSignature(ctx, m.signer, pre, SignatureScope)
	if err != nil {
		return nil, err
	}
	fund, change := buildFundAndChangeOutputs(tx, false, false)
	out := CreateEmptyFungibleAncestorChunksSMB()
	for i := 0; i < 5; i++ {
		out = append(out, ChunksFromBin(nil)...)
	}
	for _, b := range [][]byte{fund, change, Hash160(pub), nil, nil, nil, nil, sig, pub, nil, nil, nil, nil, nil, nil} {
		out = append(out, ChunksFromBin(b)...)
	}
	out = append(out, simpleMultiUnlockSuffix.Chunks()...)
	return NewScript(out), nil
}
