package b017

// txbuild.go - the two @bsv/sdk Transaction builder steps b017's classes use: fee(0) (a fixed zero fee: the
// change outputs take inputs minus outputs, equally, and are dropped when that is 0) and sign() (every input's
// template signs a snapshot of the tx taken before any unlocking script is applied).

import (
	"context"
	"errors"
	"fmt"
)

// Fee0 is `await tx.fee(0)`.
func Fee0(tx *Transaction) error {
	var totalIn uint64
	for i, in := range tx.Inputs {
		if in.SourceTransaction == nil {
			return errors.New("Source transactions are required for all inputs during fee computation")
		}
		o := outAt(in.SourceTransaction, in.SourceOutputIndex)
		if o == nil {
			return fmt.Errorf("Input %d references a source output that does not exist.", i)
		}
		if o.Satoshis == nil {
			return fmt.Errorf("Input %d source amount must be a non-negative safe integer", i)
		}
		totalIn += *o.Satoshis
	}
	var totalOut uint64
	for i, o := range tx.Outputs {
		if o.Change {
			continue
		}
		if o.Satoshis == nil {
			return fmt.Errorf("Output %d amount must be a non-negative safe integer", i)
		}
		totalOut += *o.Satoshis
	}
	if totalOut > totalIn {
		return errors.New("Transaction inputs are insufficient for the requested outputs and fee.")
	}
	change := totalIn - totalOut
	if change == 0 {
		var keep []*Output
		for _, o := range tx.Outputs {
			if !o.Change {
				keep = append(keep, o)
			}
		}
		tx.Outputs = keep
		return nil
	}
	var outs []*Output
	for _, o := range tx.Outputs {
		if o.Change {
			outs = append(outs, o)
		}
	}
	if len(outs) == 0 {
		return nil
	}
	per := change / uint64(len(outs))
	for _, o := range outs {
		o.Satoshis = U64(per)
	}
	*outs[len(outs)-1].Satoshis += change - per*uint64(len(outs))
	return nil
}

// SignTx is `await tx.sign()`: fill every input's sourceTXID across the graph, then sign each input that has a
// template on a snapshot of the unsigned tx, then apply all the unlocking scripts.
func SignTx(ctx context.Context, tx *Transaction) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = panicError(r)
		}
	}()
	for i, o := range tx.Outputs {
		if o.Satoshis == nil {
			if o.Change {
				return errors.New("There are still change outputs with uncomputed amounts. Use the fee() method to compute the change amounts and transaction fees prior to signing.")
			}
			return fmt.Errorf("One or more transaction outputs is missing an amount. Ensure all output amounts are provided before signing.")
		}
		_ = i
	}
	for i, in := range tx.Inputs {
		if in.SourceTransaction != nil && outAt(in.SourceTransaction, in.SourceOutputIndex) == nil {
			return fmt.Errorf("Input %d references a source output that does not exist.", i)
		}
	}
	fillSourceTxids(tx, map[*Transaction]bool{})
	snap := snapshot(tx)
	scripts := make([]*Script, len(tx.Inputs))
	for i, in := range tx.Inputs {
		if in.Template == nil {
			continue
		}
		us, err := in.Template.Sign(ctx, snapshot(snap), i)
		if err != nil {
			return err
		}
		scripts[i] = ScriptFromBinary(us.ToBinary())
	}
	for i, in := range tx.Inputs {
		if in.Template != nil {
			in.UnlockingScript = scripts[i]
		}
	}
	return nil
}

// snapshot copies the tx and its inputs/outputs (the source transactions are shared, as in TS).
func snapshot(tx *Transaction) *Transaction {
	c := &Transaction{Version: tx.Version, LockTime: tx.LockTime, MerklePath: tx.MerklePath}
	for _, in := range tx.Inputs {
		cp := *in
		c.Inputs = append(c.Inputs, &cp)
	}
	for _, o := range tx.Outputs {
		cp := *o
		c.Outputs = append(c.Outputs, &cp)
	}
	return c
}

// reparse is `Transaction.fromHex(tx.toHex())` with each input's source re-attached (what the classes do after
// signing).
func reparse(tx *Transaction) (*Transaction, error) {
	h, err := tx.ToHex()
	if err != nil {
		return nil, err
	}
	clean, err := TransactionFromHex(h)
	if err != nil {
		return nil, err
	}
	for i, in := range tx.Inputs {
		clean.Inputs[i].SourceTransaction = in.SourceTransaction
	}
	return clean, nil
}
