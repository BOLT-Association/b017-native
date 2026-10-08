package b017

// multibolt.go - src/tokens/MultiBOLT.ts (+ BOLT.ts): the SimpleMultiBOLT fungible token class: mint, commit,
// settle, transfer, merge, split, melt. A transcription of the reference's flows, including its defaults
// (funding from the current tx's last output, change back to the owner, fee 0).

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

// P2PKHLock is `new P2PKH().lock(pkh)`.
func P2PKHLock(pkh []byte) *Script {
	return NewScript([]Chunk{{Op: OP_DUP}, {Op: OP_HASH160}, {Op: byte(len(pkh)), Data: clone(pkh)}, {Op: OP_EQUALVERIFY}, {Op: OP_CHECKSIG}})
}

// DefaultMintBalance is mint()'s default 16-byte balance.
var DefaultMintBalance = []byte{0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f, 0, 0, 0, 0, 0, 0, 0, 0, 0}

// SimpleMultiBOLT is the fungible token builder (TS class SimpleMultiBOLT extends BOLT).
type SimpleMultiBOLT struct {
	Tx              *Transaction
	VoutIdx         int
	PrevTxs         []*Transaction
	PubKey          []byte
	IssuerPubKey    []byte
	GenesisOutpoint []byte
	Signer          Signer
	MintData        []byte
	PubKeyHash      []byte
	SkipVerify      bool
	Balance         []byte
	BalanceCommit   []byte
	OutputIndexN    []byte
}

// NewSimpleMultiBOLT is `new SimpleMultiBOLT()`.
func NewSimpleMultiBOLT() *SimpleMultiBOLT {
	return &SimpleMultiBOLT{PrevTxs: []*Transaction{}, PubKey: []byte{}, IssuerPubKey: []byte{}, GenesisOutpoint: []byte{},
		Balance: []byte{}, BalanceCommit: make([]byte, 16), OutputIndexN: []byte{0x00}}
}

// FundingSource is merge()/split()'s optional { tx, vout, key }. Vout nil = the default (the tx's last output);
// Key nil = the token's signer.
type FundingSource struct {
	Tx   *Transaction
	Vout *int
	Key  Signer
}

func zeros(n int) []byte { return make([]byte, n) }

func (b *SimpleMultiBOLT) verifyAndLog(tx *Transaction, txType string) error {
	if b.SkipVerify {
		return nil
	}
	for _, in := range tx.Inputs {
		if in.SourceTXID == "" && in.SourceTransaction != nil {
			in.SourceTXID = in.SourceTransaction.MustID()
		}
	}
	res, err := VerifyTx(tx, true)
	if err != nil {
		return err
	}
	if !res.Valid {
		return fmt.Errorf("%s tx not valid [bsv]", txType)
	}
	return nil
}

// Mint is `mint(owner, sourceTransaction, _mintData = "", balance = DefaultMintBalance)` (balance nil = default).
func (b *SimpleMultiBOLT) Mint(ctx context.Context, owner Signer, sourceTransaction *Transaction, balance []byte) (_ *SimpleMultiBOLT, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = panicError(r)
		}
	}()
	if balance == nil {
		balance = clone(DefaultMintBalance)
	}
	pubKey := owner.PublicKey()
	pkhHex := hex.EncodeToString(Hash160(pubKey))
	sourceOutputIndex := -1
	for idx, o := range sourceTransaction.Outputs {
		c := o.LockingScript.Chunks()
		if len(c) <= 2 {
			return nil, errors.New("Cannot read properties of undefined (reading 'data')")
		}
		if hex.EncodeToString(c[2].Data) == pkhHex {
			sourceOutputIndex = idx
			break
		}
	}
	if sourceOutputIndex < 0 {
		return nil, errors.New("Input 0 sourceOutputIndex must be a uint32")
	}
	b.PubKeyHash = Hash160(pubKey)
	b.Balance = balance
	tokenLock, err := SimpleMultiTemplate{}.Lock(pubKey, b.PrevTxs, SMBLockArgs{Balance: b.Balance, BalanceCommit: zeros(16),
		PubKeyHashCommit: zeros(20), PubKeyHashCommit2: zeros(20), OtherGrandparentOutpoint: zeros(36), TxoType: []byte{0x20}, OutputIndexN: []byte{0x00}})
	if err != nil {
		return nil, err
	}
	mintTx := &Transaction{Version: 2,
		Inputs:  []*Input{{SourceTransaction: sourceTransaction, SourceOutputIndex: uint32(sourceOutputIndex), Template: P2PKHUnlock(owner), Sequence: U32(0xffffffff)}},
		Outputs: []*Output{{LockingScript: tokenLock, Satoshis: U64(1)}, {Change: true, LockingScript: P2PKHLock(b.PubKeyHash)}}}
	if err := Fee0(mintTx); err != nil {
		return nil, err
	}
	if err := SignTx(ctx, mintTx); err != nil {
		return nil, err
	}
	res, err := VerifyTx(mintTx, false)
	if err != nil {
		return nil, err
	}
	if !res.Valid {
		return nil, errors.New("Mint tx not valid")
	}
	b.Tx = mintTx
	b.VoutIdx = 0
	b.PrevTxs = append(b.PrevTxs, mintTx)
	b.PubKey = pubKey
	b.IssuerPubKey = pubKey
	b.GenesisOutpoint = BuildOutpoint(mintTx, 0)
	b.Signer = owner
	return b, nil
}

func (b *SimpleMultiBOLT) findProofVout(ancestor *Transaction, key Signer) uint32 {
	pkh := hex.EncodeToString(Hash160(RecipientPubKey(key)))
	for i := 1; i < len(ancestor.Outputs)-1; i++ {
		if hex.EncodeToString(ChunkData(ancestor.Outputs[i].LockingScript, 4)) == pkh {
			return uint32(i)
		}
	}
	return 1
}

func voutLE(n uint32) []byte { return le32(n) }

// CreateTransferInputs is `createTransferInputs(to, _misc, isCommitTx, forceNoChange, fundOverride, forceNoFund)`.
func (b *SimpleMultiBOLT) CreateTransferInputs(to Recipient, isCommitTx, forceNoChange bool, fundOverride *Input, forceNoFund bool) []*Input {
	hasAncestor := !isCommitTx && len(b.PrevTxs) >= 3
	var proofVout uint32 = 1
	if hasAncestor {
		proofVout = b.findProofVout(b.PrevTxs[len(b.PrevTxs)-3], b.Signer)
	}
	nextTxo := []byte{0x20}
	if isCommitTx {
		nextTxo = []byte{0x21}
	}
	gp := []byte{}
	if hasAncestor {
		gp = voutLE(proofVout)
	}
	input := &Input{SourceTransaction: b.Tx, SourceOutputIndex: uint32(b.VoutIdx), Sequence: U32(0xffffffff),
		Template: SimpleMultiTemplate{}.Unlock(b.Signer, RecipientPubKey(to), b.PrevTxs, SMBUnlockArgs{
			ForceNoChange: forceNoChange, ForceNoFund: forceNoFund, NextBalanceCommit: []byte{}, NextTxoType: nextTxo,
			InputIndexN: []byte{0x00}, PubKeyHash2: []byte{}, GrandparentBoltVoutIdx: gp})}
	funding := fundOverride
	if funding == nil {
		vout := 0
		if b.Tx != nil {
			vout = len(b.Tx.Outputs) - 1
		}
		funding = &Input{SourceTransaction: b.Tx, SourceOutputIndex: uint32(vout), Template: P2PKHUnlock(b.Signer), Sequence: U32(0xffffffff)}
	}
	if hasAncestor {
		proof := &Input{SourceTransaction: b.PrevTxs[len(b.PrevTxs)-3], SourceOutputIndex: proofVout,
			Template: Pay2ProofUnlock(b.Signer, 0, nil), Sequence: U32(0xffffffff)}
		if forceNoFund {
			return []*Input{input, proof}
		}
		return []*Input{input, proof, funding}
	}
	if forceNoFund {
		return []*Input{input}
	}
	return []*Input{input, funding}
}

// CreateTransferOutputs is `createTransferOutputs(to, isCommitTx, forceNoChange, customChangeScript)`.
func (b *SimpleMultiBOLT) CreateTransferOutputs(to Recipient, isCommitTx, forceNoChange bool, customChangeScript *Script) ([]*Output, error) {
	toPkh := Hash160(RecipientPubKey(to))
	pkhCommit := zeros(20)
	owner := RecipientPubKey(to)
	txo := []byte{0x20}
	prevVout := 0
	if isCommitTx {
		pkhCommit = toPkh
		owner = b.PubKey
		txo = []byte{0x21}
		prevVout = b.VoutIdx
	}
	lock, err := SimpleMultiTemplate{}.Lock(owner, b.PrevTxs, SMBLockArgs{Balance: b.Balance, BalanceCommit: b.BalanceCommit,
		PubKeyHashCommit: pkhCommit, PubKeyHashCommit2: zeros(20), OtherGrandparentOutpoint: zeros(36), TxoType: txo,
		OutputIndexN: []byte{0x00}, PrevVoutIdx: prevVout})
	if err != nil {
		return nil, err
	}
	tokenOut := &Output{LockingScript: lock, Satoshis: U64(1)}
	proofOut := &Output{LockingScript: Pay2ProofLock(pkhCommit), Satoshis: U64(1)}
	changeLock := customChangeScript
	if changeLock == nil {
		if isCommitTx {
			changeLock = P2PKHLock(b.PubKeyHash)
		} else {
			changeLock = P2PKHLock(toPkh)
		}
	}
	changeOut := &Output{Change: true, LockingScript: changeLock}
	if !isCommitTx {
		if forceNoChange {
			return []*Output{tokenOut}, nil
		}
		return []*Output{tokenOut, changeOut}, nil
	}
	if forceNoChange {
		return []*Output{tokenOut, proofOut}, nil
	}
	return []*Output{tokenOut, proofOut, changeOut}, nil
}

// TransferOpts are commit/settle/transfer's optional arguments.
type TransferOpts struct {
	ForceNoChange      bool
	FundOverride       *Input
	ForceNoFund        bool
	CustomChangeScript *Script
}

func (b *SimpleMultiBOLT) finish(ctx context.Context, tx *Transaction, forceNoChange bool) (*Transaction, error) {
	if !forceNoChange {
		if err := Fee0(tx); err != nil {
			return nil, err
		}
	}
	if err := SignTx(ctx, tx); err != nil {
		return nil, err
	}
	return reparse(tx)
}

// Commit is `commit(to, miscData, forceNoChange, fundOverride, forceNoFund, customChangeScript)`.
func (b *SimpleMultiBOLT) Commit(ctx context.Context, to Recipient, o TransferOpts) (_ *SimpleMultiBOLT, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = panicError(r)
		}
	}()
	inputs := b.CreateTransferInputs(to, true, o.ForceNoChange, o.FundOverride, o.ForceNoFund)
	outputs, err := b.CreateTransferOutputs(to, true, o.ForceNoChange, o.CustomChangeScript)
	if err != nil {
		return nil, err
	}
	tx, err := b.finish(ctx, &Transaction{Version: 2, Inputs: inputs, Outputs: outputs}, o.ForceNoChange)
	if err != nil {
		return nil, err
	}
	b.Tx = tx
	if err := b.verifyAndLog(tx, "COMMIT TX"); err != nil {
		return nil, err
	}
	b.VoutIdx = 0
	b.PrevTxs = append(b.PrevTxs, tx)
	return b, nil
}

// Settle is `settle(to, miscData, forceNoChange, fundOverride, forceNoFund, customChangeScript)`.
func (b *SimpleMultiBOLT) Settle(ctx context.Context, to Recipient, o TransferOpts) (_ *SimpleMultiBOLT, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = panicError(r)
		}
	}()
	outputs, err := b.CreateTransferOutputs(to, false, o.ForceNoChange, o.CustomChangeScript)
	if err != nil {
		return nil, err
	}
	inputs := b.CreateTransferInputs(to, false, o.ForceNoChange, o.FundOverride, o.ForceNoFund)
	tx, err := b.finish(ctx, &Transaction{Version: 2, Inputs: inputs, Outputs: outputs}, o.ForceNoChange)
	if err != nil {
		return nil, err
	}
	b.Tx = tx
	if err := b.verifyAndLog(tx, "SETTLE TX"); err != nil {
		return nil, err
	}
	b.PrevTxs = append(b.PrevTxs, tx)
	if s := RecipientSigner(to); s != nil {
		b.Signer = s
	}
	b.PubKey = RecipientPubKey(to)
	b.PubKeyHash = Hash160(b.PubKey)
	return b, nil
}

// Transfer is `transfer(to, commitMisc, settleMisc, skipSettle, forceNoChange, fundOverride, forceNoFund, customChangeScript)`.
func (b *SimpleMultiBOLT) Transfer(ctx context.Context, to Recipient, skipSettle bool, o TransferOpts) (*SimpleMultiBOLT, error) {
	if _, err := b.Commit(ctx, to, o); err != nil {
		return nil, err
	}
	if !skipSettle {
		if _, err := b.Settle(ctx, to, o); err != nil {
			return nil, err
		}
	}
	return b, nil
}

var two128 = new(big.Int).Lsh(big.NewInt(1), 128)

func balanceToBig(b []byte) *big.Int {
	buf := make([]byte, 16)
	copy(buf, b)
	return new(big.Int).SetBytes(reverse(buf))
}

func bigToBalance(v *big.Int) []byte {
	x := new(big.Int).Mod(v, two128)
	out := make([]byte, 16)
	bs := x.Bytes()
	copy(out[16-len(bs):], bs)
	return reverse(out)
}

// AddBalances / SubtractBalances are the class's 128-bit LE helpers (wrapping at 2^128).
func AddBalances(a, b []byte) []byte { return bigToBalance(new(big.Int).Add(balanceToBig(a), balanceToBig(b))) }
func SubtractBalances(a, b []byte) []byte {
	return bigToBalance(new(big.Int).Sub(balanceToBig(a), balanceToBig(b)))
}

func (b *SimpleMultiBOLT) signAndClean(ctx context.Context, tx *Transaction) (*Transaction, error) {
	return b.finish(ctx, tx, false)
}

func (b *SimpleMultiBOLT) parentOutpoint() []byte {
	return clone(b.Tx.Outputs[b.VoutIdx].LockingScript.Chunks()[8].Data)
}

func fundingOf(b *SimpleMultiBOLT, fs *FundingSource) (*Transaction, uint32, Signer) {
	fundTx := b.Tx
	fundVout := len(b.Tx.Outputs) - 1
	fundKey := b.Signer
	if fs != nil {
		if fs.Tx != nil {
			fundTx = fs.Tx
		}
		if fs.Vout != nil {
			fundVout = *fs.Vout
		}
		if fs.Key != nil {
			fundKey = fs.Key
		}
	}
	return fundTx, uint32(fundVout), fundKey
}

// Merge is `merge(other, toKey, fundingSource?)`: absorb other into this token.
func (b *SimpleMultiBOLT) Merge(ctx context.Context, other *SimpleMultiBOLT, toKey Recipient, fs *FundingSource) (_ *SimpleMultiBOLT, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = panicError(r)
		}
	}()
	tpl := SimpleMultiTemplate{}
	toPkh := Hash160(RecipientPubKey(toKey))
	fundTx, fundVout, fundKey := fundingOf(b, fs)
	thisIn := &Input{SourceTransaction: b.Tx, SourceOutputIndex: uint32(b.VoutIdx), Sequence: U32(0xffffffff),
		Template: tpl.Unlock(b.Signer, RecipientPubKey(toKey), b.PrevTxs, SMBUnlockArgs{NextBalanceCommit: other.Balance,
			NextTxoType: []byte{0x25}, InputIndexN: []byte{0x00}, PubKeyHash2: []byte{}, GrandparentBoltVoutIdx: []byte{},
			InteropBoltVoutIdx: []byte{}, InteropPubKeyHash: []byte{}, InteropOutpoint: BuildOutpoint(other.Tx, uint32(other.VoutIdx)),
			InteropParentOutpoint: other.parentOutpoint()})}
	otherIn := &Input{SourceTransaction: other.Tx, SourceOutputIndex: uint32(other.VoutIdx), Sequence: U32(0xffffffff),
		Template: tpl.Unlock(other.Signer, RecipientPubKey(toKey), other.PrevTxs, SMBUnlockArgs{NextBalanceCommit: b.Balance,
			NextTxoType: []byte{0x25}, InputIndexN: []byte{0x01}, PubKeyHash2: []byte{}, GrandparentBoltVoutIdx: []byte{},
			InteropBoltVoutIdx: []byte{}, InteropPubKeyHash: Hash160(b.PubKey), InteropOutpoint: BuildOutpoint(b.Tx, uint32(b.VoutIdx)),
			InteropParentOutpoint: b.parentOutpoint()})}
	fundIn := &Input{SourceTransaction: fundTx, SourceOutputIndex: fundVout, Template: P2PKHUnlock(fundKey), Sequence: U32(0xffffffff)}
	tokenOut, err := tpl.Lock(b.PubKey, b.PrevTxs, SMBLockArgs{Balance: b.Balance, BalanceCommit: other.Balance, PubKeyHashCommit: toPkh,
		PubKeyHashCommit2: zeros(20), OtherGrandparentOutpoint: other.parentOutpoint(), TxoType: []byte{0x25}, OutputIndexN: []byte{0x00},
		PrevVoutIdx: b.VoutIdx})
	if err != nil {
		return nil, err
	}
	commitTx, err := b.signAndClean(ctx, &Transaction{Version: 2, Inputs: []*Input{thisIn, otherIn, fundIn}, Outputs: []*Output{
		{LockingScript: tokenOut, Satoshis: U64(1)}, {LockingScript: Pay2ProofLock(toPkh), Satoshis: U64(1)},
		{Change: true, LockingScript: P2PKHLock(b.PubKeyHash)}}})
	if err != nil {
		return nil, err
	}
	if err := b.verifyAndLog(commitTx, "MERGE COMMIT TX"); err != nil {
		return nil, err
	}
	b.PrevTxs = append(b.PrevTxs, commitTx)
	other.PrevTxs = append(other.PrevTxs, commitTx)

	thisAnc := b.PrevTxs[len(b.PrevTxs)-3]
	otherAnc := other.PrevTxs[len(other.PrevTxs)-3]
	thisProof := b.findProofVout(thisAnc, b.Signer)
	otherProof := b.findProofVout(otherAnc, other.Signer)
	settleIn := &Input{SourceTransaction: commitTx, SourceOutputIndex: 0, Sequence: U32(0xffffffff),
		Template: tpl.Unlock(b.Signer, RecipientPubKey(toKey), b.PrevTxs, SMBUnlockArgs{NextBalanceCommit: zeros(16),
			NextTxoType: []byte{0x24}, InputIndexN: []byte{0x00}, PubKeyHash2: []byte{}, GrandparentBoltVoutIdx: voutLE(thisProof),
			InteropBoltVoutIdx: voutLE(otherProof), InteropPubKeyHash: []byte{}, InteropOutpoint: []byte{}, InteropParentOutpoint: []byte{},
			AncestorTxBRef: otherAnc})}
	proof0 := &Input{SourceTransaction: thisAnc, SourceOutputIndex: thisProof, Template: Pay2ProofUnlock(b.Signer, 0, nil), Sequence: U32(0xffffffff)}
	proof1 := &Input{SourceTransaction: otherAnc, SourceOutputIndex: otherProof, Template: Pay2ProofUnlock(other.Signer, 0, nil), Sequence: U32(0xffffffff)}
	settleFund := &Input{SourceTransaction: commitTx, SourceOutputIndex: uint32(len(commitTx.Outputs) - 1), Template: P2PKHUnlock(b.Signer), Sequence: U32(0xffffffff)}
	merged := AddBalances(b.Balance, other.Balance)
	settleToken, err := tpl.Lock(RecipientPubKey(toKey), b.PrevTxs, SMBLockArgs{Balance: merged, BalanceCommit: zeros(16),
		PubKeyHashCommit: zeros(20), PubKeyHashCommit2: zeros(20), OtherGrandparentOutpoint: zeros(36), TxoType: []byte{0x24},
		OutputIndexN: []byte{0x00}})
	if err != nil {
		return nil, err
	}
	settleTx, err := b.signAndClean(ctx, &Transaction{Version: 2, Inputs: []*Input{settleIn, proof0, proof1, settleFund}, Outputs: []*Output{
		{LockingScript: settleToken, Satoshis: U64(1)}, {Change: true, LockingScript: P2PKHLock(Hash160(RecipientPubKey(toKey)))}}})
	if err != nil {
		return nil, err
	}
	if err := b.verifyAndLog(settleTx, "MERGE SETTLE TX"); err != nil {
		return nil, err
	}
	b.Tx = settleTx
	b.VoutIdx = 0
	b.PrevTxs = append(b.PrevTxs, settleTx)
	if s := RecipientSigner(toKey); s != nil {
		b.Signer = s
	}
	b.PubKey = RecipientPubKey(toKey)
	b.PubKeyHash = Hash160(b.PubKey)
	b.Balance = merged
	b.BalanceCommit = zeros(16)
	return b, nil
}

// Split is `split(toKeyA, toKeyB, splitBalanceCommit, fundingSource?)`: returns [this (piece A), piece B].
func (b *SimpleMultiBOLT) Split(ctx context.Context, toKeyA, toKeyB Recipient, splitBalanceCommit []byte, fs *FundingSource) (_ *SimpleMultiBOLT, _ *SimpleMultiBOLT, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = panicError(r)
		}
	}()
	tpl := SimpleMultiTemplate{}
	pkhA := Hash160(RecipientPubKey(toKeyA))
	pkhB := Hash160(RecipientPubKey(toKeyB))
	fundTx, fundVout, fundKey := fundingOf(b, fs)
	tokenIn := &Input{SourceTransaction: b.Tx, SourceOutputIndex: uint32(b.VoutIdx), Sequence: U32(0xffffffff),
		Template: tpl.Unlock(b.Signer, RecipientPubKey(toKeyA), b.PrevTxs, SMBUnlockArgs{NextBalanceCommit: splitBalanceCommit,
			NextTxoType: []byte{0x23}, InputIndexN: []byte{0x00}, PubKeyHash2: pkhB})}
	fundIn := &Input{SourceTransaction: fundTx, SourceOutputIndex: fundVout, Template: P2PKHUnlock(fundKey), Sequence: U32(0xffffffff)}
	tokenOut, err := tpl.Lock(b.PubKey, b.PrevTxs, SMBLockArgs{Balance: b.Balance, BalanceCommit: splitBalanceCommit, PubKeyHashCommit: pkhA,
		PubKeyHashCommit2: pkhB, OtherGrandparentOutpoint: zeros(36), TxoType: []byte{0x23}, OutputIndexN: []byte{0x00}, PrevVoutIdx: b.VoutIdx})
	if err != nil {
		return nil, nil, err
	}
	commitTx, err := b.signAndClean(ctx, &Transaction{Version: 2, Inputs: []*Input{tokenIn, fundIn}, Outputs: []*Output{
		{LockingScript: tokenOut, Satoshis: U64(1)}, {LockingScript: Pay2ProofLock(pkhA), Satoshis: U64(1)},
		{LockingScript: Pay2ProofLock(pkhB), Satoshis: U64(1)}, {Change: true, LockingScript: P2PKHLock(b.PubKeyHash)}}})
	if err != nil {
		return nil, nil, err
	}
	if err := b.verifyAndLog(commitTx, "SPLIT COMMIT TX"); err != nil {
		return nil, nil, err
	}
	b.PrevTxs = append(b.PrevTxs, commitTx)

	anc := b.PrevTxs[len(b.PrevTxs)-3]
	ancProof := b.findProofVout(anc, b.Signer)
	settleIn := &Input{SourceTransaction: commitTx, SourceOutputIndex: 0, Sequence: U32(0xffffffff),
		Template: tpl.Unlock(b.Signer, []byte{}, b.PrevTxs, SMBUnlockArgs{NextBalanceCommit: []byte{}, NextTxoType: []byte{0x22},
			InputIndexN: []byte{0x00}, PubKeyHash2: []byte{}, GrandparentBoltVoutIdx: voutLE(ancProof)})}
	proofIn := &Input{SourceTransaction: anc, SourceOutputIndex: ancProof, Template: Pay2ProofUnlock(b.Signer, 0, nil), Sequence: U32(0xffffffff)}
	settleFund := &Input{SourceTransaction: commitTx, SourceOutputIndex: uint32(len(commitTx.Outputs) - 1), Template: P2PKHUnlock(b.Signer), Sequence: U32(0xffffffff)}
	mainBalance := SubtractBalances(b.Balance, splitBalanceCommit)
	out0, err := tpl.Lock(RecipientPubKey(toKeyA), b.PrevTxs, SMBLockArgs{Balance: mainBalance, BalanceCommit: zeros(16), PubKeyHashCommit: zeros(20),
		PubKeyHashCommit2: zeros(20), OtherGrandparentOutpoint: zeros(36), TxoType: []byte{0x22}, OutputIndexN: []byte{0x00}})
	if err != nil {
		return nil, nil, err
	}
	out1, err := tpl.Lock(RecipientPubKey(toKeyB), b.PrevTxs, SMBLockArgs{Balance: splitBalanceCommit, BalanceCommit: zeros(16), PubKeyHashCommit: zeros(20),
		PubKeyHashCommit2: zeros(20), OtherGrandparentOutpoint: zeros(36), TxoType: []byte{0x22}, OutputIndexN: []byte{0x01}})
	if err != nil {
		return nil, nil, err
	}
	settleTx, err := b.signAndClean(ctx, &Transaction{Version: 2, Inputs: []*Input{settleIn, proofIn, settleFund}, Outputs: []*Output{
		{LockingScript: out0, Satoshis: U64(1)}, {LockingScript: out1, Satoshis: U64(1)},
		{Change: true, LockingScript: P2PKHLock(Hash160(RecipientPubKey(toKeyA)))}}})
	if err != nil {
		return nil, nil, err
	}
	if err := b.verifyAndLog(settleTx, "SPLIT SETTLE TX"); err != nil {
		return nil, nil, err
	}
	b.Tx = settleTx
	b.VoutIdx = 0
	b.PrevTxs = append(b.PrevTxs, settleTx)
	if s := RecipientSigner(toKeyA); s != nil {
		b.Signer = s
	}
	b.PubKey = RecipientPubKey(toKeyA)
	b.PubKeyHash = Hash160(b.PubKey)
	b.Balance = mainBalance

	t := NewSimpleMultiBOLT()
	t.Tx = settleTx
	t.VoutIdx = 1
	t.PrevTxs = append([]*Transaction{}, b.PrevTxs...)
	t.Signer = RecipientSigner(toKeyB)
	t.PubKey = RecipientPubKey(toKeyB)
	t.PubKeyHash = Hash160(t.PubKey)
	t.IssuerPubKey = b.IssuerPubKey
	t.GenesisOutpoint = b.GenesisOutpoint
	t.Balance = splitBalanceCommit
	t.SkipVerify = b.SkipVerify
	return b, t, nil
}

// Melt is `melt(meltPubKeyHash?)` (nil = the owner's pubKeyHash).
func (b *SimpleMultiBOLT) Melt(ctx context.Context, meltPubKeyHash []byte) (_ *SimpleMultiBOLT, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = panicError(r)
		}
	}()
	vout := 0
	if b.Tx != nil {
		vout = len(b.Tx.Outputs) - 1
	}
	pkh := meltPubKeyHash
	if pkh == nil {
		pkh = b.PubKeyHash
	}
	meltTx := &Transaction{Version: 2,
		Inputs: []*Input{
			{SourceTransaction: b.Tx, SourceOutputIndex: uint32(b.VoutIdx), Template: SimpleMultiTemplate{}.Melt(b.Signer, nil, nil), Sequence: U32(0xffffffff)},
			{SourceTransaction: b.Tx, SourceOutputIndex: uint32(vout), Template: P2PKHUnlock(b.Signer), Sequence: U32(0xffffffff)},
		},
		Outputs: []*Output{{Change: true, LockingScript: P2PKHLock(pkh)}}}
	tx, err := b.finish(ctx, meltTx, false)
	if err != nil {
		return nil, err
	}
	b.Tx = tx
	if err := b.verifyAndLog(tx, "MELT TX"); err != nil {
		return nil, err
	}
	return b, nil
}
