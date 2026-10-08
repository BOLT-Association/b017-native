package b017

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestVectorsFuzz replays the differential corpus (vectors/fuzz.json, vectors/gen/fuzz.test.ts): batches the
// reference accepted, each with one seeded mutation, and the reference's verdict on it.
func TestVectorsFuzz(t *testing.T) {
	path := filepath.Join(vectorsDir(), "fuzz.json")
	if p := os.Getenv("B017_FUZZ_FILE"); p != "" {
		path = p
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skip("no vectors/fuzz.json")
	}
	var corpus struct {
		Cases []struct {
			Kind     string          `json:"kind"`
			Base     string          `json:"base"`
			Mutation string          `json:"mutation"`
			Batch    []arg           `json:"batch"`
			Opts     json.RawMessage `json:"opts"`
			Known    []string        `json:"known"`
			Result   json.RawMessage `json:"result"`
		} `json:"cases"`
		Nodes map[string]vNode `json:"nodes"`
	}
	if err := json.Unmarshal(b, &corpus); err != nil {
		t.Fatal(err)
	}
	agree, refused := 0, 0
	for i, c := range corpus.Cases {
		g := newGraph(t)
		g.extra = corpus.Nodes
		known := map[string]bool{}
		for _, k := range c.Known {
			known[k] = true
		}
		r := &replay{t: t, g: g}
		r.rec.Opts = c.Opts
		o, _, _ := r.opts()
		if o.IsKnownBlockRoot != nil {
			o.IsKnownBlockRoot = func(root string, h uint64) bool { return known[jsKey(h, root)] }
		}
		var batch []any
		for _, it := range c.Batch {
			batch = append(batch, g.tx(it.ID))
		}
		var got any
		if c.Kind == "verifyEvents" {
			got = VerifyEvents(batch, o)
		} else {
			got = VerifyEvent(batch, o)
		}
		if msg := resultsMatch(t, got, c.Result); msg != "" {
			t.Errorf("case %d (%s; %s on %s): %s", i, c.Kind, c.Mutation, c.Base, msg)
			continue
		}
		agree++
		var w struct{ OK bool `json:"ok"` }
		_ = json.Unmarshal(c.Result, &w)
		if !w.OK {
			refused++
		}
	}
	t.Logf("fuzz: %d/%d cases agree with the reference (%d refused by both)", agree, len(corpus.Cases), refused)
}

func jsKey(h uint64, root string) string { return fmtUint(h) + ":" + root }

func fmtUint(h uint64) string {
	b, _ := json.Marshal(h)
	return string(b)
}
