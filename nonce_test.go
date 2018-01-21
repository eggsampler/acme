package acme

import "testing"

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

	ns.newNonceURL = "http://google.com/"
	if _, err = ns.Nonce(); err == nil {
		t.Fatal("expected error, got none")
	}

	ns.newNonceURL = testClient.Directory.NewNonce
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
