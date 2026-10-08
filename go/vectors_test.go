package b017

// vectors_test.go - replay the calls recorded from the TypeScript reference's own test suite (vectors/).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

type vNode struct {
	V   *uint32 `json:"v"`
	Lt  *uint32 `json:"lt"`
	Ins []struct {
		Txid *string `json:"txid"`
		Vout *uint32 `json:"vout"`
		Seq  *uint32 `json:"seq"`
		Us   *string `json:"us"`
		Src  *string `json:"src"`
	} `json:"ins"`
	Outs []struct {
		Sat *uint64 `json:"sat"`
		Ls  *string `json:"ls"`
	} `json:"outs"`
	Mp *string `json:"mp"`
}

var (
	nodesOnce sync.Once
	nodes     map[string]vNode
)

func vectorsDir() string { return filepath.Join("..", "vectors") }

func loadNodes(t testing.TB) map[string]vNode {
	nodesOnce.Do(func() {
		b, err := os.ReadFile(filepath.Join(vectorsDir(), "nodes.json"))
		if err != nil {
			panic(err)
		}
		if err := json.Unmarshal(b, &nodes); err != nil {
			panic(err)
		}
	})
	return nodes
}

func loadCalls(t testing.TB, name string) []map[string]json.RawMessage {
	b, err := os.ReadFile(filepath.Join(vectorsDir(), "calls", name+".json"))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var out []map[string]json.RawMessage
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return out
}

// graph rebuilds tx nodes into Transactions; one object per node id within a record, as the reference had.
type graph struct {
	t     testing.TB
	nodes map[string]vNode
	extra map[string]vNode
	memo  map[string]*Transaction
}

func newGraph(t testing.TB) *graph {
	return &graph{t: t, nodes: loadNodes(t), memo: map[string]*Transaction{}}
}

func (g *graph) tx(id string) *Transaction {
	if t, ok := g.memo[id]; ok {
		return t
	}
	n, ok := g.nodes[id]
	if !ok {
		n, ok = g.extra[id]
	}
	if !ok {
		g.t.Fatalf("unknown node %s", id)
	}
	t := &Transaction{}
	g.memo[id] = t
	if n.V != nil {
		t.Version = *n.V
	}
	if n.Lt != nil {
		t.LockTime = *n.Lt
	}
	for _, in := range n.Ins {
		i := &Input{}
		if in.Txid != nil {
			i.SourceTXID = *in.Txid
		}
		if in.Vout != nil {
			i.SourceOutputIndex = *in.Vout
		}
		if in.Seq != nil {
			i.Sequence = U32(*in.Seq)
		}
		if in.Us != nil {
			i.UnlockingScript = MustScriptFromHex(*in.Us)
		}
		if in.Src != nil {
			i.SourceTransaction = g.tx(*in.Src)
		}
		t.Inputs = append(t.Inputs, i)
	}
	for _, o := range n.Outs {
		out := &Output{}
		if o.Sat != nil {
			out.Satoshis = U64(*o.Sat)
		}
		if o.Ls != nil {
			out.LockingScript = MustScriptFromHex(*o.Ls)
		}
		t.Outputs = append(t.Outputs, out)
	}
	if n.Mp != nil {
		mp, err := MerklePathFromHex(*n.Mp)
		if err != nil {
			g.t.Fatalf("node %s merkle path: %v", id, err)
		}
		t.MerklePath = mp
	}
	return t
}

// nodeID is the content address the recorder gives a tx graph (vectors/gen/ser.ts).
func nodeID(t *Transaction, memo map[*Transaction]string) string {
	if id, ok := memo[t]; ok {
		return id
	}
	memo[t] = "cycle"
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`{"v":%d,"lt":%d,"ins":[`, t.Version, t.LockTime))
	str := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	for k, in := range t.Inputs {
		if k > 0 {
			sb.WriteString(",")
		}
		txid := "null"
		if in.SourceTXID != "" {
			txid = str(in.SourceTXID)
		}
		seq := "null"
		if in.Sequence != nil {
			seq = fmt.Sprint(*in.Sequence)
		}
		us := "null"
		if in.UnlockingScript != nil {
			us = str(in.UnlockingScript.ToHex())
		}
		src := "null"
		if in.SourceTransaction != nil {
			src = str(nodeID(in.SourceTransaction, memo))
		}
		sb.WriteString(fmt.Sprintf(`{"txid":%s,"vout":%d,"seq":%s,"us":%s,"src":%s}`, txid, in.SourceOutputIndex, seq, us, src))
	}
	sb.WriteString(`],"outs":[`)
	for k, o := range t.Outputs {
		if k > 0 {
			sb.WriteString(",")
		}
		sat := "null"
		if o.Satoshis != nil {
			sat = fmt.Sprint(*o.Satoshis)
		}
		ls := "null"
		if o.LockingScript != nil {
			ls = str(o.LockingScript.ToHex())
		}
		sb.WriteString(fmt.Sprintf(`{"sat":%s,"ls":%s}`, sat, ls))
	}
	mp := "null"
	if t.MerklePath != nil {
		mp = str(t.MerklePath.ToHex())
	}
	sb.WriteString(`],"mp":` + mp + "}")
	h := sha256.Sum256([]byte(sb.String()))
	id := hex.EncodeToString(h[:])[:32]
	memo[t] = id
	return id
}

// arg is a recorded argument (vectors/gen/ser.ts Graph.input).
type arg struct {
	T     string          `json:"t"`
	ID    string          `json:"id"`
	V     json.RawMessage `json:"v"`
	Hex   string          `json:"hex"`
	Pub   string          `json:"pub"`
	Key   *string         `json:"key"`
	Items []arg           `json:"items"`
}

func (a arg) bytes(t testing.TB) []byte {
	if a.T == "undefined" {
		return nil
	}
	if a.T != "bytes" && a.T != "u8" {
		t.Fatalf("arg %q is not bytes", a.T)
	}
	b, err := hex.DecodeString(a.Hex)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (a arg) signer(t testing.TB) Signer {
	var keyHex string
	switch a.T {
	case "key":
		keyHex = a.Hex
	case "signer":
		if a.Key == nil {
			t.Skipf("signer %s has no recorded key", a.Pub)
		}
		keyHex = *a.Key
	default:
		t.Fatalf("arg %q is not a key", a.T)
	}
	k, err := ec.PrivateKeyFromHex(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	return KeySigner{Key: k}
}

func (a arg) boolean() bool {
	var b bool
	_ = json.Unmarshal(a.V, &b)
	return b
}

func (a arg) number() uint64 {
	var n uint64
	_ = json.Unmarshal(a.V, &n)
	return n
}

func str(raw json.RawMessage) string {
	var s string
	_ = json.Unmarshal(raw, &s)
	return s
}

func label(rec map[string]json.RawMessage, i int) string {
	return fmt.Sprintf("#%d %s :: %s", i, str(rec["file"]), str(rec["test"]))
}
