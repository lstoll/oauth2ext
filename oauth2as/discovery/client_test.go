package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/tink-crypto/tink-go/v2/keyset"
)

func TestBackgroundRefresh(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	m := http.NewServeMux()
	ts := httptest.NewServer(m)
	t.Cleanup(ts.Close)

	h := PublicHandle()
	handleFn := func() *keyset.Handle {
		return h
	}

	kh, err := NewKeysHandler(handleFn, 1*time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	m.Handle("/jwks.json", kh)

	pm := &ProviderMetadata{
		Issuer:                ts.URL,
		JWKSURI:               ts.URL + "/jwks.json",
		AuthorizationEndpoint: "/auth",
		TokenEndpoint:         "/token",
	}

	ch, err := NewConfigurationHandler(pm, WithCoreDefaults())
	if err != nil {
		t.Fatalf("error creating handler: %v", err)
	}
	m.Handle(oidcwk, ch)

	cl, err := NewClient(ctx, ts.URL, WithBackgroundJWKSRefresh(1*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}

	// capture the original keys
	origKIDs := getKIDs(cl.PublicHandle())

	// set the handle to a new set, let it get refreshed.
	h = PublicHandle()
	time.Sleep(5 * time.Millisecond)

	newKIDs := getKIDs(cl.PublicHandle()) // on the block

	if reflect.DeepEqual(origKIDs, newKIDs) {
		t.Errorf("keys did not refresh, orig: %v new: %v", origKIDs, newKIDs)
	}

	// discard our reference to the client, and force a GC. The GC should stop
	// the background refresh.
	refresher := cl.refresher
	if refresher.stopped {
		t.Error("refresher should not be stopped after GC")
	}

	cl = nil
	runtime.GC()

	time.Sleep(5 * time.Millisecond)

	if !refresher.stopped {
		t.Error("refresher should be stopped after GC")
	}
}

func getKIDs(h *keyset.Handle) []int {
	var ret []int
	for _, ki := range h.KeysetInfo().KeyInfo {
		ret = append(ret, int(ki.KeyId))
	}
	return ret
}
