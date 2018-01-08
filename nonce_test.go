package acme

import (
	"net/http"
	"testing"
)

func TestNonceStack_Nonce(t *testing.T) {
	ns := nonceStack{}

	ns.push("test")
	if len(ns.stack) != 1 {
		t.Fatalf("expected stack size of 1, got: %d", len(ns.stack))
	}

	nonce, err := ns.Nonce()
	if err != nil {
		t.Fatalf("unexpected error popping nonce from stack: %v", err)
	}
	if nonce != "test" {
		t.Fatalf("bad nonce returned from stack, expected %q got %q", "test", nonce)
	}

	if _, err = ns.Nonce(); err == nil {
		t.Fatal("expected error, got none")
	}

	ns.newNonceUrl = "http://google.com/"
	if _, err = ns.Nonce(); err == nil {
		t.Fatal("expected error, got none")
	}

	ns.newNonceUrl = client.dir.NewNonce
	nonce, err = ns.Nonce()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if nonce == "" {
		t.Fatal("no nonce returned")
	}
	if len(ns.stack) != 0 {
		t.Fatal("expected empty stack")
	}
}

func TestNonceStack_RoundTrip(t *testing.T) {
	req, err := http.NewRequest("GET", testDirectoryUrl, nil)
	if err != nil {
		t.Fatalf("error creating request: %v", err)
	}

	ns := nonceStack{}
	resp, err := ns.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(ns.stack) != 1 {
		t.Fatalf("expected stack size of 1, got: %d", len(ns.stack))
	}

	nonceReceived, err := ns.Nonce()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	nonceSent := resp.Header.Get("Replay-Nonce")
	if nonceReceived != nonceSent {
		t.Fatalf("error getting nonce, expected %s, got %s", nonceSent, nonceReceived)
	}
}
