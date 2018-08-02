package acme

import (
	"testing"
)

func TestNonceStack(t *testing.T) {
	ns := nonceStack{}

	ns.push("test")
	if len(ns.stack) != 1 {
		t.Fatalf("expected stack size of 1, got: %d", len(ns.stack))
	}

	nonce := ns.pop()
	if nonce != "test" {
		t.Fatalf("bad nonce returned from stack, expected %q got %q", "test", nonce)
	}

	if nonce := ns.pop(); nonce != "" {
		t.Fatalf("expected no nonce, got: %v", nonce)
	}

	if len(ns.stack) != 0 {
		t.Fatal("expected empty stack")
	}
}
