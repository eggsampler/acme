package acme

import "testing"

func TestWhitelistHosts(t *testing.T) {
	w := WhitelistHosts("hello")

	if err := w("no"); err == nil {
		t.Fatal("expected error, got none")
	}

	if err := w("hello"); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}
