package b017

// singleancestor.go - src/lib/single/singleAncestor.ts: the NFT ancestor-piece unlock args a settle carries
// when it reaches back over a chain of >= 4 txs.

// PieceNames are the 26 NFT ancestor-piece names, in unlock-arg order.
var PieceNames = []string{
	"Version",
	"Vin1Outpoint", "Vin1FundOutpoint", "Vin1ChangeOutput", "Vin1BeneficiaryPubKeyHash",
	"Vin1Sig", "Vin1PubKey", "Vin1CTXHeader",
	"Vin1CTXScriptCodePubKeyHash", "Vin1CTXScriptCodePubKeyHashCommitment", "Vin1CTXScriptCodeTxoType",
	"Vin1CTXScriptCodeParentOutpoint", "Vin1CTXScriptCodeGrandparentOutpoint",
	"Vin1CTXFooter", "Vin1NSequence",
	"Vin2Outpoint", "Vin2Script", "Vin2NSequence",
	"Vout1PubKeyHash", "Vout1PubKeyHashCommitment", "Vout1TxoType", "Vout1ParentOutpoint", "Vout1GrandparentOutpoint",
	"ChangeValue", "ChangeScript", "NLockTime",
}

// AuthPieceNames are AuthBolt's 27: PieceNames with "Vin1AuthOrMiscData" after "Vin1Outpoint".
var AuthPieceNames = append([]string{"Version", "Vin1Outpoint", "Vin1AuthOrMiscData"}, PieceNames[2:]...)

// SingleLayout is one NFT-family contract's unlock-arg layout.
type SingleLayout struct {
	PieceNames []string
	HasAuth    bool
}

// MinSimpleLayout: 37 args = 26 ancestor pieces + 11 current-tx args.
var MinSimpleLayout = SingleLayout{PieceNames: PieceNames, HasAuth: false}

// AuthBoltLayout: 39 args = authOrMiscData + 27 ancestor pieces + 11 current-tx args.
var AuthBoltLayout = SingleLayout{PieceNames: AuthPieceNames, HasAuth: true}

// CurrentArgsStart is `currentArgsStart`: the unlock index of the first current-tx arg.
func CurrentArgsStart(l SingleLayout) int {
	n := len(l.PieceNames)
	if l.HasAuth {
		n++
	}
	return n
}

// AncestorPiece is `ancestorPiece`: one named piece from an ancestor commit tx.
func AncestorPiece(name string, ancestorTx *Transaction, leadingValuePushes int, layout SingleLayout) []byte {
	in0 := ancestorTx.Inputs[0]
	var in1 *Input
	if len(ancestorTx.Inputs) > 1 {
		in1 = ancestorTx.Inputs[1]
	}
	u := in0.UnlockingScript
	if u == nil {
		panic(errorf("Cannot read properties of undefined (reading 'chunks')"))
	}
	cur := CurrentArgsStart(layout)
	spentLock := ScriptFromBinary(ChunkData(u, cur+8))
	sd := func(i int) []byte { return clone(ChunkData(spentLock, leadingValuePushes+i)) }
	outLock := ancestorTx.Outputs[0].LockingScript
	od := func(i int) []byte { return clone(ChunkData(outLock, leadingValuePushes+i)) }
	var changeOut *Output
	if len(ancestorTx.Outputs) > 2 {
		changeOut = ancestorTx.Outputs[2]
	}
	uc := func(i int) []byte { return clone(ChunkData(u, i)) }
	switch name {
	case "Version":
		return le32(ancestorTx.Version)
	case "Vin1Outpoint":
		return SpentOutpoint(ancestorTx, 0)
	case "Vin1AuthOrMiscData":
		return uc(0)
	case "Vin1FundOutpoint":
		return uc(cur)
	case "Vin1ChangeOutput":
		return uc(cur + 1)
	case "Vin1BeneficiaryPubKeyHash":
		return uc(cur + 2)
	case "Vin1Sig":
		return uc(cur + 3)
	case "Vin1PubKey":
		return uc(cur + 4)
	case "Vin1CTXHeader":
		return uc(cur + 5)
	case "Vin1CTXScriptCodePubKeyHash":
		return sd(0)
	case "Vin1CTXScriptCodePubKeyHashCommitment":
		return sd(1)
	case "Vin1CTXScriptCodeTxoType":
		return sd(2)
	case "Vin1CTXScriptCodeParentOutpoint":
		return sd(3)
	case "Vin1CTXScriptCodeGrandparentOutpoint":
		return sd(4)
	case "Vin1CTXFooter":
		return uc(cur + 9)
	case "Vin1NSequence":
		return le32(in0.Seq())
	case "Vin2Outpoint":
		if in1 == nil {
			return []byte{}
		}
		return SpentOutpoint(ancestorTx, 1)
	case "Vin2Script":
		if in1 == nil {
			return []byte{}
		}
		if in1.UnlockingScript == nil {
			panic(errorf("Cannot read properties of undefined (reading 'toBinary')"))
		}
		return in1.UnlockingScript.ToBinary()
	case "Vin2NSequence":
		if in1 == nil {
			return []byte{}
		}
		return le32(in1.Seq())
	case "Vout1PubKeyHash":
		return od(0)
	case "Vout1PubKeyHashCommitment":
		return od(1)
	case "Vout1TxoType":
		return od(2)
	case "Vout1ParentOutpoint":
		return od(3)
	case "Vout1GrandparentOutpoint":
		return od(4)
	case "ChangeValue":
		if changeOut == nil {
			return []byte{}
		}
		return le64(changeOut.Sats())
	case "ChangeScript":
		if changeOut == nil {
			return []byte{}
		}
		return changeOut.LockingScript.ToBinary()
	case "NLockTime":
		return le32(ancestorTx.LockTime)
	default:
		return []byte{}
	}
}

// SingleAncestorPieces is `singleAncestorPieces`: every piece of the layout, in unlock order.
func SingleAncestorPieces(ancestorTx *Transaction, leadingValuePushes int, layout SingleLayout) [][]byte {
	out := make([][]byte, 0, len(layout.PieceNames))
	for _, n := range layout.PieceNames {
		out = append(out, AncestorPiece(n, ancestorTx, leadingValuePushes, layout))
	}
	return out
}
