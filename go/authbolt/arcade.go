package authbolt

// arcade.go - core.js arcadeBroadcaster and provenInHeaders: how the sidecar decides that an anchor is known to
// the network (mined into the headers we hold, already seen by Arcade, or accepted on submission).

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	b017 "github.com/BOLT-Association/b017-native/go"
)

var seen = map[string]bool{"SEEN_ON_NETWORK": true, "SEEN_ON_MULTIPLE_NODES": true, "ACCEPTED_BY_NETWORK": true, "MINED": true, "IMMUTABLE": true}
var refused = map[string]bool{"REJECTED": true, "DOUBLE_SPEND_ATTEMPTED": true}

// ProvenInHeaders is core.js provenInHeaders: tx carries a merkle path that proves it into our own headers.
func ProvenInHeaders(ctx context.Context, tx *b017.Transaction, headers b017.HeaderSource) bool {
	if tx.MerklePath == nil || headers == nil {
		return false
	}
	id, err := tx.ID()
	if err != nil {
		return false
	}
	root, err := tx.MerklePath.ComputeRoot(id)
	if err != nil {
		return false
	}
	ok, err := headers.IsValidRootForHeight(ctx, root, tx.MerklePath.BlockHeight)
	return err == nil && ok
}

// Arcade is core.js arcadeBroadcaster's configuration.
type Arcade struct {
	URL     string
	Headers b017.HeaderSource
	HTTP    *http.Client
	Timeout time.Duration // default 20 s
	Every   time.Duration // default 500 ms
}

func (a Arcade) client() *http.Client {
	if a.HTTP != nil {
		return a.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (a Arcade) statusOf(ctx context.Context, txid string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL+"/tx/"+txid, nil)
	if err != nil {
		return ""
	}
	res, err := a.client().Do(req)
	if err != nil {
		return ""
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return ""
	}
	var body struct {
		TxStatus string `json:"txStatus"`
	}
	if json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&body) != nil {
		return ""
	}
	return body.TxStatus
}

func detail(s string) *string { return &s }

// Broadcaster is arcadeBroadcaster(...): the b017 AnchorBroadcaster that asks Arcade.
func (a Arcade) Broadcaster() b017.AnchorBroadcaster {
	timeout, every := a.Timeout, a.Every
	if timeout == 0 {
		timeout = 20 * time.Second
	}
	if every == 0 {
		every = 500 * time.Millisecond
	}
	return func(ctx context.Context, tx *b017.Transaction) (b017.AnchorBroadcastResult, error) {
		txid, err := tx.ID()
		if err != nil {
			return b017.AnchorBroadcastResult{}, err
		}
		if ProvenInHeaders(ctx, tx, a.Headers) {
			return b017.AnchorBroadcastResult{Status: "already-seen", Detail: detail("mined")}, nil
		}
		if known := a.statusOf(ctx, txid); seen[known] {
			return b017.AnchorBroadcastResult{Status: "already-seen", Detail: detail(known)}, nil
		}
		extended := true
		for _, in := range tx.Inputs {
			if in.SourceTransaction == nil {
				extended = false
			}
		}
		var raw []byte
		if extended {
			raw, err = tx.ToBinaryEF()
		} else {
			raw, err = tx.ToBinary()
		}
		if err != nil {
			return b017.AnchorBroadcastResult{}, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.URL+"/tx", bytes.NewReader([]byte(hex.EncodeToString(raw))))
		if err != nil {
			return b017.AnchorBroadcastResult{}, err
		}
		req.Header.Set("content-type", "text/plain")
		res, err := a.client().Do(req)
		if err != nil {
			return b017.AnchorBroadcastResult{}, err
		}
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		res.Body.Close()
		if res.StatusCode != 200 && res.StatusCode != 202 {
			text := string(body)
			if len(text) > 200 {
				text = text[:200]
			}
			return b017.AnchorBroadcastResult{Status: "rejected", Detail: detail(fmt.Sprintf("arcade %d: %s", res.StatusCode, text))}, nil
		}
		end := time.Now().Add(timeout)
		for time.Now().Before(end) {
			st := a.statusOf(ctx, txid)
			if seen[st] {
				return b017.AnchorBroadcastResult{Status: "accepted", Detail: detail(st)}, nil
			}
			if refused[st] {
				return b017.AnchorBroadcastResult{Status: "rejected", Detail: detail(st)}, nil
			}
			select {
			case <-ctx.Done():
				return b017.AnchorBroadcastResult{}, ctx.Err()
			case <-time.After(every):
			}
		}
		return b017.AnchorBroadcastResult{Status: "rejected", Detail: detail("no network status from arcade in time")}, nil
	}
}

// ChainRoots is the part of p2p's headers.Chain the verifier needs: whether `root` (display hex) is the merkle
// root of the active header at `height`.
type ChainRoots interface {
	RootActive(height uint32, root string) bool
}

// HeadersOf adapts a ChainRoots (p2pd's own verified header chain) to b017's HeaderSource; only an active root is a
// yes, as verify-server.js headersTracker does.
func HeadersOf(c ChainRoots) b017.HeaderSource { return chainHeaders{c} }

type chainHeaders struct{ c ChainRoots }

func (h chainHeaders) IsValidRootForHeight(_ context.Context, root string, height uint64) (bool, error) {
	if height > 0xffffffff {
		return false, nil
	}
	return h.c.RootActive(uint32(height), root), nil
}
