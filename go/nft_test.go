package b017

import (
	"encoding/json"
	"testing"
)

// txList is a recorded prevTxs argument: a list of tx nodes ([] is recorded as empty bytes).
func (a arg) txList(t testing.TB, g *graph) []*Transaction {
	switch a.T {
	case "undefined":
		return nil
	case "bytes":
		if a.Hex != "" {
			t.Fatalf("prevTxs recorded as non-empty bytes")
		}
		return []*Transaction{}
	case "list":
		out := []*Transaction{}
		for _, it := range a.Items {
			if it.T != "tx" {
				t.Fatalf("prevTxs item %q", it.T)
			}
			out = append(out, g.tx(it.ID))
		}
		return out
	}
	t.Fatalf("prevTxs kind %q", a.T)
	return nil
}

func argAt(args []arg, i int) arg {
	if i < len(args) {
		return args[i]
	}
	return arg{T: "undefined"}
}

func lockArgs(t *testing.T, args []arg) [6][]byte {
	var out [6][]byte
	for i := 0; i < 6; i++ {
		out[i] = argAt(args, i).bytes(t)
	}
	return out
}

func TestVectorsLockNFT(t *testing.T) {
	for _, c := range []struct {
		name string
		lock func(a [6][]byte) *Script
	}{
		{"lock.MinSimple", func(a [6][]byte) *Script { return MinSimpleTemplate{}.Lock(a[0], a[1], a[2], a[3], a[4], a[5]) }},
		{"lock.AuthBolt", func(a [6][]byte) *Script { return AuthBoltTemplate{}.Lock(a[0], a[1], a[2], a[3], a[4], a[5]) }},
	} {
		for i, rec := range loadCalls(t, c.name) {
			var args []arg
			_ = json.Unmarshal(rec["args"], &args)
			if got := c.lock(lockArgs(t, args)).ToHex(); got != str(rec["result"]) {
				t.Errorf("%s %s: lock differs", c.name, label(rec, i))
			}
		}
	}
}

func init() {
	signBuilders["sign.MinSimple"] = func(t *testing.T, g *graph, method string, args []arg) (UnlockTemplate, error) {
		if method == "melt" {
			return MinSimpleTemplate{}.Melt(args[0].signer(t)), nil
		}
		return MinSimpleTemplate{}.Unlock(args[0].signer(t), argAt(args, 1).bytes(t), argAt(args, 2).txList(t, g),
			argAt(args, 3).boolean(), argAt(args, 4).boolean()), nil
	}
	signBuilders["sign.AuthBolt"] = func(t *testing.T, g *graph, method string, args []arg) (UnlockTemplate, error) {
		if method == "melt" {
			return AuthBoltTemplate{}.Melt(args[0].signer(t)), nil
		}
		return AuthBoltTemplate{}.Unlock(args[0].signer(t), argAt(args, 1).bytes(t), argAt(args, 2).txList(t, g),
			argAt(args, 3).bytes(t), argAt(args, 4).boolean(), argAt(args, 5).boolean())
	}
}

func TestVectorsTemplateAuthBoltRefusesLongData(t *testing.T) {
	for i, rec := range loadCalls(t, "template.AuthBolt") {
		var args []arg
		_ = json.Unmarshal(rec["args"], &args)
		g := newGraph(t)
		_, err := AuthBoltTemplate{}.Unlock(args[0].signer(t), argAt(args, 1).bytes(t), argAt(args, 2).txList(t, g), argAt(args, 3).bytes(t), false, false)
		if err == nil || err.Error() != str(rec["throws"]) {
			t.Errorf("%s: error %v, want %q", label(rec, i), err, str(rec["throws"]))
		}
	}
}
