package b017

// beef.go - src/lib/scanner/beef.ts: the off-chain data package, Atomic BEEF (BRC-95) over BEEF V2 (BRC-96).

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// IsBeef is `isBeef`: the hex string / bytes begin with a BEEF magic (V1, V2 or Atomic).
func IsBeef(x any) bool {
	var head string
	switch v := x.(type) {
	case string:
		if len(v) > 8 {
			v = v[:8]
		}
		head = strings.ToLower(v)
	case []byte:
		if len(v) > 4 {
			v = v[:4]
		}
		head = hex.EncodeToString(v)
	default:
		return false
	}
	return head == "0100beef" || head == "0200beef" || head == "01010101"
}

// ToAtomicBeef is `toAtomicBeef`: tx and every attached source tx (with merkle paths where known), Atomic BEEF
// over BEEF V2.
func ToAtomicBeef(tx *Transaction) ([]byte, error) {
	fillSourceTxids(tx, map[*Transaction]bool{})
	beef := NewBeef(BEEF_V2)
	if _, err := beef.MergeTransaction(tx); err != nil {
		return nil, err
	}
	id, err := tx.ID()
	if err != nil {
		return nil, err
	}
	return beef.ToBinaryAtomic(id)
}

// FromBeef is `fromBeef`: parse BEEF V2 (plain or Atomic) into its subject transaction, ancestors wired in.
// `input` is a hex string or bytes.
func FromBeef(input any) (tx *Transaction, err error) {
	defer func() {
		if r := recover(); r != nil {
			tx, err = nil, panicError(r)
		}
	}()
	var bytes []byte
	switch v := input.(type) {
	case string:
		bytes = jsHexToArray(v)
	case []byte:
		bytes = v
	default:
		return nil, errors.New("fromBeef: expected hex or bytes")
	}
	beef, err := BeefFromBinary(bytes)
	if err != nil {
		return nil, err
	}
	if beef.Version != BEEF_V2 {
		return nil, errors.New("BEEF V1 (BRC-62) is not accepted; use BEEF V2 (BRC-96) / Atomic BEEF (BRC-95)")
	}
	ok, err := beef.IsValid(false)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("BEEF is not self-contained: a tx is neither proven by a BUMP nor has all its inputs in the BEEF")
	}
	for _, t := range beef.Txs {
		if t.Tx() != nil && t.bumpIndex == nil && len(t.Tx().Inputs) == 0 {
			id := t.Txid()
			if len(id) > 8 {
				id = id[:8]
			}
			return nil, fmt.Errorf("BEEF is not self-contained: tx %s has no inputs and no BUMP", id)
		}
	}
	subject := beef.AtomicTxid
	if subject == "" {
		for i := len(beef.Txs) - 1; i >= 0; i-- {
			if beef.Txs[i].Tx() != nil {
				subject = beef.Txs[i].Txid()
				break
			}
		}
	}
	var t *Transaction
	if subject != "" {
		t = beef.FindAtomicTransaction(subject)
	}
	if t == nil {
		return nil, errors.New("BEEF has no subject transaction")
	}
	return t, nil
}

// panicError turns a recovered panic into the error the TS throw would have been.
func panicError(r any) error {
	if e, ok := r.(error); ok {
		return e
	}
	return fmt.Errorf("%v", r)
}
