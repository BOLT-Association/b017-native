package b017

// spend.go - the reference's `new Spend({...}).validate()` (@bsv/sdk Spend) on go-sdk's interpreter.
// TS relaxes a spend by the SPENDING tx's version: version > 1 runs after-Genesis / after-Chronicle rules with no
// malleability policy (SIGPUSHONLY, CLEANSTACK, MINIMALDATA, LOW_S, NULLDUMMY off); version 1 runs pre-Genesis
// with that policy on. TS validate() throws on every failure (it never returns false), so a failure here is an
// error whose text is go-sdk's (compared by prefix only, see PROGRESS.md).

import (
	"encoding/hex"
	"errors"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	gscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// SpendParams are the TS Spend constructor parameters.
type SpendParams struct {
	SourceTXID         string
	SourceOutputIndex  uint32
	LockingScript      *Script
	SourceSatoshis     uint64
	TransactionVersion uint32
	OtherInputs        []OutpointRef
	UnlockingScript    *Script
	InputSequence      uint32
	InputIndex         int
	Outputs            []*Output
	LockTime           uint32
}

// Validate is `new Spend(p).validate()`: nil when the spend is valid, else the interpreter's error.
func Validate(p SpendParams) error {
	if p.InputIndex < 0 || p.InputIndex > len(p.OtherInputs) {
		return errors.New("inputIndex out of range")
	}
	gtx := transaction.NewTransaction()
	gtx.Version = p.TransactionVersion
	gtx.LockTime = p.LockTime
	cur := OutpointRef{SourceTXID: p.SourceTXID, SourceOutputIndex: p.SourceOutputIndex, Sequence: U32(p.InputSequence)}
	refs := append([]OutpointRef{}, p.OtherInputs[:p.InputIndex]...)
	refs = append(refs, cur)
	refs = append(refs, p.OtherInputs[p.InputIndex:]...)
	for k, r := range refs {
		h, err := refHash(r)
		if err != nil {
			return err
		}
		in := &transaction.TransactionInput{SourceTXID: h, SourceTxOutIndex: r.SourceOutputIndex, SequenceNumber: seqOr(r.Sequence)}
		if k == p.InputIndex {
			in.UnlockingScript = toGoScript(p.UnlockingScript)
		} else {
			in.UnlockingScript = &gscript.Script{}
		}
		gtx.Inputs = append(gtx.Inputs, in)
	}
	for _, o := range p.Outputs {
		gtx.Outputs = append(gtx.Outputs, &transaction.TransactionOutput{Satoshis: o.Sats(), LockingScript: toGoScript(o.LockingScript)})
	}
	prev := &transaction.TransactionOutput{Satoshis: p.SourceSatoshis, LockingScript: toGoScript(p.LockingScript)}
	opts := []interpreter.ExecutionOptionFunc{
		interpreter.WithTx(gtx, p.InputIndex, prev),
		interpreter.WithForkID(),
	}
	if p.TransactionVersion > 1 {
		opts = append(opts, interpreter.WithAfterChronicle())
	} else {
		// go-sdk (like Bitcoin Core) refuses CLEANSTACK without BIP16; BIP16 only changes P2SH-shaped locks,
		// which TS Spend never special-cases and b017 never builds.
		opts = append(opts, interpreter.WithBeforeGenesis(), interpreter.WithFlags(
			scriptflag.Bip16|scriptflag.VerifySigPushOnly|scriptflag.VerifyCleanStack|scriptflag.VerifyMinimalData|
				scriptflag.VerifyLowS|scriptflag.StrictMultiSig|scriptflag.VerifyStrictEncoding|scriptflag.VerifyDERSignatures))
	}
	return interpreter.NewEngine().Execute(opts...)
}

func refHash(r OutpointRef) (*chainhash.Hash, error) {
	if r.SourceTXID != "" {
		return chainhash.NewHashFromHex(r.SourceTXID)
	}
	if r.SourceTransaction == nil {
		return nil, errors.New("Missing sourceTransaction for input")
	}
	h, err := r.SourceTransaction.Hash()
	if err != nil {
		return nil, err
	}
	return chainhash.NewHash(h)
}

func toGoScript(s *Script) *gscript.Script {
	if s == nil {
		return &gscript.Script{}
	}
	b := gscript.Script(s.ToBinary())
	return &b
}

// VerifyTxResult is verifyTx's result (scriptExecutions keeps only each input's verdict).
type VerifyTxResult struct {
	Valid      bool
	Executions []bool
}

// VerifyTx is boltLib `verifyTx`: run every input on the interpreter (each must have its source tx attached and
// an unlocking script), then check the output total. Errors are what the TS function throws.
func VerifyTx(tx *Transaction, skipOutputCheck bool) (VerifyTxResult, error) {
	var res VerifyTxResult
	var inputTotal uint64
	txid, err := tx.ID()
	if err != nil {
		return res, err
	}
	for i, input := range tx.Inputs {
		if input.SourceTransaction == nil {
			return res, errorf("Verification failed: input %d of %s is missing its source transaction.", i, txid)
		}
		if input.UnlockingScript == nil {
			return res, errorf("Verification failed: input %d of %s is missing its unlocking script.", i, txid)
		}
		src := input.SourceOutput()
		if src == nil {
			return res, errors.New("Cannot read properties of undefined (reading 'satoshis')")
		}
		inputTotal += src.Sats()
		sourceTxid, err := input.SourceTransaction.ID()
		if err != nil {
			return res, err
		}
		if input.SourceTXID == "" {
			input.SourceTXID = sourceTxid
		}
		if err := Validate(SpendParams{
			SourceTXID: input.SourceTXID, SourceOutputIndex: input.SourceOutputIndex, LockingScript: src.LockingScript,
			SourceSatoshis: src.Sats(), TransactionVersion: tx.Version, OtherInputs: RefsOf(tx.Inputs, i),
			UnlockingScript: input.UnlockingScript, InputSequence: input.Seq(), InputIndex: i, Outputs: tx.Outputs,
			LockTime: tx.LockTime,
		}); err != nil {
			return res, err
		}
		res.Executions = append(res.Executions, true)
	}
	var outputTotal uint64
	for _, o := range tx.Outputs {
		if o.Satoshis == nil {
			return res, errors.New("Every output must have a defined amount during verification.")
		}
		outputTotal += *o.Satoshis
	}
	if !skipOutputCheck && outputTotal > inputTotal {
		return res, errors.New("Output total greater than input total")
	}
	res.Valid = true
	return res, nil
}

var _ = hex.EncodeToString
