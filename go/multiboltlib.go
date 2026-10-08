package b017

// multiboltlib.go - src/lib/multi/multiBoltLib.ts: SimpleMultiBolt ancestor reconstruction and CTX helpers.

import (
	"errors"
	"fmt"
)

const (
	args2ctxSMB   = 192
	skipSMB       = 178
	txoTypeIdxSMB = 6
)

// readVarIntNum is the ts-sdk Reader's non-strict readVarIntNum (it throws when data runs out).
func readVarIntNum(b []byte, pos *int) uint64 {
	need := func(n int) {
		if *pos+n > len(b) {
			panic(errors.New("Reader read exceeds available data"))
		}
	}
	need(1)
	first := b[*pos]
	*pos++
	switch first {
	case 0xfd:
		need(2)
		v := uint64(b[*pos]) | uint64(b[*pos+1])<<8
		*pos += 2
		return v
	case 0xfe:
		need(4)
		v := uint64(b[*pos]) | uint64(b[*pos+1])<<8 | uint64(b[*pos+2])<<16 | uint64(b[*pos+3])<<24
		*pos += 4
		return v
	case 0xff:
		need(8)
		var v uint64
		for i := 7; i >= 0; i-- {
			v = v<<8 | uint64(b[*pos+i])
		}
		*pos += 8
		if v > 1<<53 {
			panic(errors.New("number too large to retain precision - use readVarIntBn"))
		}
		return v
	}
	return uint64(first)
}

// jsSlice is Array.prototype.slice for the callers here, which pass 0 <= a <= e: both ends clamp to the length.
func jsSlice(b []byte, a, e int) []byte {
	if e > len(b) {
		e = len(b)
	}
	if a > e {
		a = e
	}
	return clone(b[a:e])
}

// vinCTX rebuilds the ctx from a token input's unlock (header + lockLen + lockScriptCode + footer), writes it as
// one push, and returns that serialisation and where the scriptCode starts; ok false when chunk 192 is absent.
func vinCTX(tx *Transaction, vin int) (ctx, scriptBin []byte, scriptCodeStart int, ok bool) {
	if vin < 0 || vin >= len(tx.Inputs) || tx.Inputs[vin].UnlockingScript == nil {
		return nil, nil, 0, false
	}
	c := tx.Inputs[vin].UnlockingScript.Chunks()
	if len(c) <= args2ctxSMB {
		return nil, nil, 0, false
	}
	data := func(i int) []byte {
		if i < len(c) && c[i].Data != nil {
			return c[i].Data
		}
		return nil
	}
	ctx = append(append(append(append([]byte{}, data(args2ctxSMB)...), data(args2ctxSMB+5)...), data(args2ctxSMB+3)...), data(args2ctxSMB+4)...)
	scriptBin = NewScript(nil).WriteBin(ctx).ToBinary()
	headerLen := len(scriptBin) - len(ctx)
	return ctx, scriptBin, 104 + headerLen, true
}

// getVinCTXPieceSMB: piece 0 = ctxHeader (104 bytes); piece 2 = the bytes after the scriptCode (footer).
func getVinCTXPieceSMB(tx *Transaction, vin, piece int) []byte {
	ctx, scriptBin, start, ok := vinCTX(tx, vin)
	if !ok {
		return []byte{}
	}
	buf := jsSlice(scriptBin, start, len(scriptBin))
	pos := 0
	n := readVarIntNum(buf, &pos)
	if piece == 0 {
		return jsSlice(ctx, 0, 104)
	}
	return jsSlice(scriptBin, start+int(n)+pos, len(scriptBin))
}

// getVinCTXDataArgSMB: lock data arg argIdx (0..10) out of the reconstructed scriptCode.
func getVinCTXDataArgSMB(tx *Transaction, vin, argIdx int) []byte {
	_, scriptBin, start, ok := vinCTX(tx, vin)
	if !ok {
		return []byte{}
	}
	buf := jsSlice(scriptBin, start, len(scriptBin))
	pos := 0
	n := readVarIntNum(buf, &pos)
	code := ScriptFromBinary(jsSlice(buf, pos, pos+int(n)))
	cs := code.Chunks()
	if argIdx >= len(cs) {
		return []byte{}
	}
	if cs[argIdx].Op == 0 {
		return []byte{}
	}
	if cs[argIdx].Data == nil {
		return []byte{}
	}
	return clone(cs[argIdx].Data)
}

// determineTxTypeSMB is `(data[0] || -1).toString(16)`: "-1" for a 0x00 or absent byte, unpadded hex otherwise.
func determineTxTypeSMB(tx *Transaction) string {
	c := tx.Outputs[0].LockingScript.Chunks()
	if txoTypeIdxSMB >= len(c) || len(c[txoTypeIdxSMB].Data) == 0 || c[txoTypeIdxSMB].Data[0] == 0 {
		return "-1"
	}
	return fmt.Sprintf("%x", c[txoTypeIdxSMB].Data[0])
}

// SMBPieceNames are the 89 SimpleMultiBolt ancestor piece names per ancestor.
var SMBPieceNames = []string{
	"Version",
	"Vin1Outpoint",
	"Vin1GrandparentProofVoutIdx", "Vin1InteropProofVoutIdx",
	"Vin1InteropPubKeyHash", "Vin1InteropOutpoint", "Vin1InteropParentOutpoint",
	"Vin1FundOutpoint", "Vin1ChangeOutput",
	"Vin1PubKeyHash1", "Vin1PubKeyHash2", "Vin1NextBalanceCommit", "Vin1NextTxoType", "Vin1InputIndexN",
	"Vin1Sig", "Vin1PubKey",
	"Vin1CTXHeader", "Vin1CTXBalance", "Vin1CTXBalanceCommit",
	"Vin1CTXPubKeyHash", "Vin1CTXPubKeyHashCommit", "Vin1CTXPubKeyHashCommit2",
	"Vin1CTXOtherGrandparentOutpoint",
	"Vin1CTXTxoType", "Vin1CTXOutputIndexN",
	"Vin1CTXParentOutpoint", "Vin1CTXGrandparentOutpoint", "Vin1CTXIssuerPubKey",
	"Vin1CTXFooter", "Vin1NSequence",
	"Vin2Outpoint",
	"Vin2GrandparentProofVoutIdx", "Vin2InteropProofVoutIdx",
	"Vin2InteropPubKeyHash", "Vin2InteropOutpoint", "Vin2InteropParentOutpoint",
	"Vin2FundOutpoint", "Vin2ChangeOutput",
	"Vin2PubKeyHash1", "Vin2PubKeyHash2", "Vin2NextBalanceCommit", "Vin2NextTxoType", "Vin2InputIndexN",
	"Vin2Sig", "Vin2PubKey",
	"Vin2CTXHeader", "Vin2CTXBalance", "Vin2CTXBalanceCommit",
	"Vin2CTXPubKeyHash", "Vin2CTXPubKeyHashCommit", "Vin2CTXPubKeyHashCommit2",
	"Vin2CTXOtherGrandparentOutpoint",
	"Vin2CTXTxoType", "Vin2CTXOutputIndexN",
	"Vin2CTXParentOutpoint", "Vin2CTXGrandparentOutpoint", "Vin2CTXIssuerPubKey",
	"Vin2CTXFooter", "Vin2NSequence",
	"VinFundOutpoint", "VinFundScript", "VinFundNSequence",
	"Vout1Balance", "Vout1BalanceCommit",
	"Vout1PubKeyHash", "Vout1PubKeyHashCommit", "Vout1PubKeyHashCommit2",
	"Vout1OtherGrandparentOutpoint",
	"Vout1TxoType", "Vout1OutputIndexN",
	"Vout1ParentOutpoint", "Vout1GrandparentOutpoint", "Vout1IssuerPubKey",
	"Vout2Balance", "Vout2BalanceCommit",
	"Vout2PubKeyHash", "Vout2PubKeyHashCommit", "Vout2PubKeyHashCommit2",
	"Vout2OtherGrandparentOutpoint",
	"Vout2TxoType", "Vout2OutputIndexN",
	"Vout2ParentOutpoint", "Vout2GrandparentOutpoint", "Vout2IssuerPubKey",
	"ProofPubKeyHash1", "ProofPubKeyHash2",
	"ChangeValue", "ChangeScript", "NLockTime",
}

var vinPieceOffsets = map[string]int{
	"GrandparentProofVoutIdx": 0, "InteropProofVoutIdx": 1, "InteropPubKeyHash": 2, "InteropOutpoint": 3,
	"InteropParentOutpoint": 4, "FundOutpoint": 5, "ChangeOutput": 6, "PubKeyHash1": 7, "PubKeyHash2": 8,
	"NextBalanceCommit": 9, "NextTxoType": 10, "InputIndexN": 11, "Sig": 12, "PubKey": 13,
}

var ctxArgIdx = map[string]int{
	"CTXBalance": 0, "CTXBalanceCommit": 1, "CTXPubKeyHash": 2, "CTXPubKeyHashCommit": 3, "CTXPubKeyHashCommit2": 4,
	"CTXOtherGrandparentOutpoint": 5, "CTXTxoType": 6, "CTXOutputIndexN": 7, "CTXParentOutpoint": 8,
	"CTXGrandparentOutpoint": 9, "CTXIssuerPubKey": 10,
}

var voutArgIdx = map[string]int{
	"Balance": 0, "BalanceCommit": 1, "PubKeyHash": 2, "PubKeyHashCommit": 3, "PubKeyHashCommit2": 4,
	"OtherGrandparentOutpoint": 5, "TxoType": 6, "OutputIndexN": 7, "ParentOutpoint": 8, "GrandparentOutpoint": 9,
	"IssuerPubKey": 10,
}

// SMBAncestorPiece is multiBoltLib `ancestorPiece(name, tx)`.
func SMBAncestorPiece(name string, tx *Transaction) []byte {
	txType := determineTxTypeSMB(tx)
	twoTokenInputs := txType == "25"
	twoBolts := txType == "23"
	fundVin := len(tx.Inputs) - 1
	changeVout := len(tx.Outputs) - 1
	hasChange := false
	if changeVout >= 0 && tx.Outputs[changeVout].LockingScript != nil {
		hasChange = len(tx.Outputs[changeVout].LockingScript.Chunks()) == 5
	}
	limit := 1
	if twoTokenInputs {
		limit = 2
	}
	hasFunding := len(tx.Inputs) > limit

	vinPiece := func(vin int, rest string) []byte {
		switch {
		case rest == "Outpoint":
			return SpentOutpoint(tx, vin)
		case rest == "CTXHeader":
			return getVinCTXPieceSMB(tx, vin, 0)
		case rest == "CTXFooter":
			return getVinCTXPieceSMB(tx, vin, 2)
		case rest == "NSequence":
			return VinSequence(tx, vin)
		}
		if k, ok := vinPieceOffsets[rest]; ok {
			return VinChunk(tx, vin, skipSMB+k)
		}
		if k, ok := ctxArgIdx[rest]; ok {
			return getVinCTXDataArgSMB(tx, vin, k)
		}
		return []byte{}
	}
	switch {
	case name == "Version":
		return TxVersion(tx)
	case len(name) > 4 && name[:4] == "Vin1":
		return vinPiece(0, name[4:])
	case len(name) > 4 && name[:4] == "Vin2":
		if !twoTokenInputs {
			return []byte{}
		}
		return vinPiece(1, name[4:])
	case name == "VinFundOutpoint":
		if !hasFunding {
			return []byte{}
		}
		return SpentOutpoint(tx, fundVin)
	case name == "VinFundScript":
		if !hasFunding {
			return []byte{}
		}
		return VinScript(tx, fundVin)
	case name == "VinFundNSequence":
		if !hasFunding {
			return []byte{}
		}
		return VinSequence(tx, fundVin)
	case len(name) > 5 && name[:5] == "Vout1":
		return VoutChunk(tx, 0, voutArgIdx[name[5:]])
	case len(name) > 5 && name[:5] == "Vout2":
		if !twoBolts {
			return []byte{}
		}
		return VoutChunk(tx, 1, voutArgIdx[name[5:]])
	case name == "ProofPubKeyHash1":
		return VoutChunk(tx, 1, 4)
	case name == "ProofPubKeyHash2":
		if !twoBolts {
			return []byte{}
		}
		return VoutChunk(tx, 2, 4)
	case name == "ChangeValue":
		if !hasChange {
			return []byte{}
		}
		return OutputValue(tx, changeVout)
	case name == "ChangeScript":
		if !hasChange {
			return []byte{}
		}
		return OutputScript(tx, changeVout)
	case name == "NLockTime":
		return TxLockTime(tx)
	}
	return []byte{}
}

// CreateEmptyFungibleAncestorChunksSMB is the 178 OP_0 ancestor chunks a melt carries.
func CreateEmptyFungibleAncestorChunksSMB() []Chunk { return EmptySingleAncestorChunks(skipSMB) }
