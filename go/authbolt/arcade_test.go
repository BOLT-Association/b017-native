package authbolt

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	b017 "github.com/BOLT-Association/b017-native/go"
)

// fakeArcade answers GET /tx/{id} with the current status and POST /tx with `post`, switching the status to
// `after` once posted.
type fakeArcade struct {
	mu     sync.Mutex
	status string
	post   int
	after  string
	body   string
	posted bool
}

func (f *fakeArcade) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/tx/"):
		if f.status == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		fmt.Fprintf(w, `{"txStatus":%q}`, f.status)
	case r.Method == http.MethodPost && r.URL.Path == "/tx":
		b, _ := io.ReadAll(r.Body)
		f.body = string(b)
		f.posted = true
		w.WriteHeader(f.post)
		if f.post == 202 {
			f.status = f.after
		} else {
			fmt.Fprint(w, "bad tx")
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type roots map[string]bool

func (r roots) RootActive(h uint32, root string) bool { return r[fmt.Sprintf("%d:%s", h, root)] }

func anchor(t *testing.T) *b017.Transaction {
	return identity(t, key(7))
}

func TestArcadeBroadcaster(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name, status, after, want, detail string
		post                              int
	}{
		{name: "already seen", status: "SEEN_ON_NETWORK", want: "already-seen", detail: "SEEN_ON_NETWORK"},
		{name: "accepted after submission", post: 202, after: "MINED", want: "accepted", detail: "MINED"},
		{name: "refused on submission", post: 400, want: "rejected", detail: "arcade 400: bad tx"},
		{name: "rejected after submission", post: 202, after: "DOUBLE_SPEND_ATTEMPTED", want: "rejected", detail: "DOUBLE_SPEND_ATTEMPTED"},
		{name: "no status in time", post: 202, after: "QUEUED", want: "rejected", detail: "no network status from arcade in time"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeArcade{status: c.status, post: c.post, after: c.after}
			srv := httptest.NewServer(f)
			defer srv.Close()
			b := Arcade{URL: srv.URL, Timeout: 150 * time.Millisecond, Every: 20 * time.Millisecond}.Broadcaster()
			tx := anchor(t)
			r, err := b(ctx, tx)
			if err != nil {
				t.Fatal(err)
			}
			if r.Status != c.want || r.Detail == nil || *r.Detail != c.detail {
				t.Fatalf("%+v (%v), want %s / %s", r, *r.Detail, c.want, c.detail)
			}
			if f.posted {
				ef, _ := tx.ToBinaryEF()
				if f.body != hex.EncodeToString(ef) {
					t.Fatalf("posted %s…, want the Extended Format", f.body[:20])
				}
			}
		})
	}
}

func TestArcadeTrustsOwnHeaders(t *testing.T) {
	tx := anchor(t)
	// a tx with a merkle path into a header we hold is mined: Arcade is not asked
	id, _ := tx.ID()
	mp, _ := b017.NewMerklePath(5, [][]*b017.Leaf{{{Offset: 0, Hash: id, HasHash: true, Txid: true}}}, true)
	tx.MerklePath = mp
	f := &fakeArcade{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	b := Arcade{URL: srv.URL, Headers: HeadersOf(roots{"5:" + id: true})}.Broadcaster()
	r, err := b(context.Background(), tx)
	if err != nil || r.Status != "already-seen" || *r.Detail != "mined" || f.posted {
		t.Fatalf("%+v %v posted=%v", r, err, f.posted)
	}
	if ProvenInHeaders(context.Background(), tx, HeadersOf(roots{})) {
		t.Fatal("a root we do not hold proved the tx")
	}
	if ok, _ := HeadersOf(roots{}).IsValidRootForHeight(context.Background(), "00", 1<<40); ok {
		t.Fatal("a height beyond uint32 was a known root")
	}
}

// TestVerifierWithHeaders runs a presentation whose anchor is proven by p2pd-style headers (HeadersOf).
func TestVerifierWithHeaders(t *testing.T) {
	owner, app := key(7), key(8)
	mint := identity(t, owner)
	data := authData("03", app)
	db, _ := hex.DecodeString(data)
	pkg := present(t, mint, owner, b017.Hash160(owner.PublicKey()), db)
	srv := httptest.NewServer(&fakeArcade{status: "SEEN_ON_NETWORK"})
	defer srv.Close()
	v := &Verifier{Broadcast: Arcade{URL: srv.URL}.Broadcaster(), Headers: HeadersOf(roots{})}
	r, err := v.Verify(context.Background(), pkg, hex.EncodeToString(app.PublicKey()), data)
	if err != nil || !r.OK || r.Purpose != "refresh" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := DecodeAuthData("09" + data[2:]); err == nil || err.Error() != "unknown purpose tag 0x09" {
		t.Fatalf("tag: %v", err)
	}
	if _, err := DecodeAuthData(data[:2] + "04" + data[4:]); err == nil || err.Error() != "the auth data does not carry a valid app key" {
		t.Fatalf("app key: %v", err)
	}
	if _, ok := ReadToken(&b017.Transaction{}, 0); ok {
		t.Fatal("an empty tx held a token")
	}
}
