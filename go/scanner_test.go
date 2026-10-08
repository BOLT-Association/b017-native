package b017

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// sdkTail matches reasons whose tail is an SDK's own error text (compared by prefix only; PROGRESS.md).
var sdkTail = []*regexp.Regexp{
	regexp.MustCompile(`^(script execution failed: tx [0-9a-f]{8} input \d+: )(.*)$`),
	regexp.MustCompile(`^(unverifiable input: )(.*)$`),
	regexp.MustCompile(`^(malformed transaction hex: )(.*)$`),
	regexp.MustCompile(`^(invalid BEEF: )(.*)$`),
	regexp.MustCompile(`^(.*its merkle path does not prove it \()(.*)$`),
}

// b017Tails are tails that are b017's own words even after one of the prefixes above.
var b017Tails = []string{"no unlocking script", "the script evaluated false", "its source tx was not supplied", "BEEF "}

// reasonsMatch reports whether a Go reason matches the reference's: exactly, or (for an SDK-worded tail) by prefix.
var reasonStats = map[string]int{}

func reasonsMatch(got, want string) bool {
	if got == want {
		reasonStats["exact"]++
		return true
	}
	reasonStats["prefix"]++
	for _, re := range sdkTail {
		w := re.FindStringSubmatch(want)
		if w == nil {
			continue
		}
		for _, own := range b017Tails {
			if strings.HasPrefix(w[2], own) {
				return false
			}
		}
		g := re.FindStringSubmatch(got)
		return g != nil && g[1] == w[1]
	}
	return false
}

// resultsMatch compares a Go result (marshalled) with the recorded TS result, field for field.
func resultsMatch(t *testing.T, got any, want json.RawMessage) string {
	gb, _ := json.Marshal(got)
	var g, w map[string]any
	_ = json.Unmarshal(gb, &g)
	_ = json.Unmarshal(want, &w)
	gr, _ := g["reason"].(string)
	wr, _ := w["reason"].(string)
	if !reasonsMatch(gr, wr) {
		return fmt.Sprintf("reason\n got %q\nwant %q", gr, wr)
	}
	delete(g, "reason")
	delete(w, "reason")
	if !reflect.DeepEqual(g, w) {
		return fmt.Sprintf("result\n got %s\nwant %s", gb, want)
	}
	return ""
}

type scanRec struct {
	Batch struct {
		T     string `json:"t"`
		Items []arg  `json:"items"`
	} `json:"batch"`
	Opts        json.RawMessage `json:"opts"`
	Broadcaster json.RawMessage `json:"broadcaster"`
	Calls       []struct {
		Cb     string          `json:"cb"`
		Root   string          `json:"root"`
		Height uint64          `json:"height"`
		Ans    json.RawMessage `json:"ans"`
		Throws *string         `json:"throws"`
		Tx     string          `json:"tx"`
	} `json:"calls"`
	Result json.RawMessage `json:"result"`
}

type replay struct {
	t      *testing.T
	rec    scanRec
	g      *graph
	errors []string
	bcast  int
}

func (r *replay) answer(cb, root string, height uint64) (bool, bool) {
	for _, c := range r.rec.Calls {
		if c.Cb == cb && c.Root == root && c.Height == height {
			if c.Throws != nil {
				return false, true
			}
			var b bool
			if err := json.Unmarshal(c.Ans, &b); err != nil {
				return false, false
			}
			return b, false
		}
	}
	r.errors = append(r.errors, fmt.Sprintf("Go asked %s(%s, %d), which the reference never asked", cb, root, height))
	return false, false
}

func (r *replay) opts() (ScanOpts, HeaderSource, bool) {
	var o ScanOpts
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(r.rec.Opts, &raw); err != nil {
		return o, nil, true
	}
	if _, isJSON := raw["t"]; isJSON {
		return o, nil, true // opts were null / not an object: defaults
	}
	if v, ok := raw["expectedType"]; ok {
		var s string
		if json.Unmarshal(v, &s) == nil {
			o.ExpectedType = TokenType(s)
		}
	}
	if v, ok := raw["requireBroadcastable"]; ok {
		var b bool
		_ = json.Unmarshal(v, &b)
		o.RequireBroadcastable = b
	}
	if v, ok := raw["trustedIssuerPubKey"]; ok {
		var a arg
		_ = json.Unmarshal(v, &a)
		switch a.T {
		case "str":
			o.TrustedIssuerPubKey = str(a.V)
		case "bytes", "u8":
			o.TrustedIssuerPubKey = a.bytes(r.t)
		}
	}
	if v, ok := raw["isKnownBlockRoot"]; ok && str(v) == "fn" {
		o.IsKnownBlockRoot = func(root string, height uint64) bool {
			ans, throws := r.answer("isKnownBlockRoot", root, height)
			if throws {
				panic("isKnownBlockRoot threw")
			}
			return ans
		}
	}
	var tracker HeaderSource
	if v, ok := raw["chainTracker"]; ok && str(v) == "fn" {
		tracker = trackerFunc(func(root string, height uint64) (bool, error) {
			ans, throws := r.answer("chainTracker", root, height)
			if throws {
				return false, fmt.Errorf("tracker threw")
			}
			return ans, nil
		})
	}
	return o, tracker, true
}

type trackerFunc func(root string, height uint64) (bool, error)

func (f trackerFunc) IsValidRootForHeight(_ context.Context, root string, height uint64) (bool, error) {
	return f(root, height)
}

func (r *replay) broadcaster() AnchorBroadcaster {
	if str(r.rec.Broadcaster) != "fn" {
		return nil
	}
	return func(_ context.Context, tx *Transaction) (AnchorBroadcastResult, error) {
		var calls []int
		for i, c := range r.rec.Calls {
			if c.Cb == "broadcast" {
				calls = append(calls, i)
			}
		}
		if r.bcast >= len(calls) {
			r.errors = append(r.errors, "Go broadcast more anchors than the reference")
			return AnchorBroadcastResult{Status: "rejected"}, nil
		}
		c := r.rec.Calls[calls[r.bcast]]
		r.bcast++
		if got := nodeID(tx, map[*Transaction]string{}); got != c.Tx {
			r.errors = append(r.errors, fmt.Sprintf("broadcast anchor %s, reference broadcast %s", got, c.Tx))
		}
		if c.Throws != nil {
			return AnchorBroadcastResult{}, fmt.Errorf("%s", *c.Throws)
		}
		var ans map[string]any
		if json.Unmarshal(c.Ans, &ans) != nil || ans == nil {
			return AnchorBroadcastResult{}, nil
		}
		res := AnchorBroadcastResult{}
		if s, ok := ans["status"].(string); ok {
			res.Status = s
		} else if v, ok := ans["status"]; ok {
			res.Status = fmt.Sprint(v)
		}
		if d, ok := ans["detail"].(string); ok {
			res.Detail = &d
		}
		return res, nil
	}
}

func (r *replay) batch() []any {
	var out []any
	for _, it := range r.rec.Batch.Items {
		switch it.T {
		case "tx":
			out = append(out, r.g.tx(it.ID))
		case "str":
			out = append(out, str(it.V))
		case "u8", "bytes":
			out = append(out, it.bytes(r.t))
		default:
			out = append(out, struct{}{})
		}
	}
	return out
}

func runScanVectors(t *testing.T, name string, run func(r *replay) any) {
	recs := loadCalls(t, name)
	skipped := 0
	for i, raw := range recs {
		if _, bad := raw["unserializable"]; bad {
			skipped++
			continue
		}
		b, _ := json.Marshal(raw)
		var rec scanRec
		_ = json.Unmarshal(b, &rec)
		if rec.Batch.T != "array" {
			skipped++ // a non-array batch: Go's []any cannot be one
			continue
		}
		t.Run(label(raw, i), func(t *testing.T) {
			r := &replay{t: t, rec: rec, g: newGraph(t)}
			got := run(r)
			if msg := resultsMatch(t, got, rec.Result); msg != "" {
				t.Error(msg)
			}
			for _, e := range r.errors {
				t.Error(e)
			}
		})
	}
	t.Logf("%s: %d records, %d not representable in Go (non-array batch); reasons so far exact %d, prefix-only %d", name, len(recs), skipped, reasonStats["exact"], reasonStats["prefix"])
}

func TestVectorsVerifyEvents(t *testing.T) {
	runScanVectors(t, "verifyEvents", func(r *replay) any {
		o, _, _ := r.opts()
		return VerifyEvents(r.batch(), o)
	})
}

func TestVectorsVerifyEvent(t *testing.T) {
	runScanVectors(t, "verifyEvent", func(r *replay) any {
		o, _, _ := r.opts()
		return VerifyEvent(r.batch(), o)
	})
}

func TestVectorsVerifyAndBroadcast(t *testing.T) {
	runScanVectors(t, "verifyAndBroadcast", func(r *replay) any {
		o, tracker, _ := r.opts()
		return VerifyAndBroadcast(context.Background(), r.batch(), r.broadcaster(), o, tracker)
	})
}
