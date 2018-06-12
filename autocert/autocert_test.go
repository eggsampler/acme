package autocert

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWhitelistHosts(t *testing.T) {
	w := WhitelistHosts("hello")

	if err := w("no"); err == nil {
		t.Fatal("expected error, got none")
	}

	if err := w("hello"); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAutoCert_HTTPHandler(t *testing.T) {
	a := AutoCert{}
	handler := a.HTTPHandler(nil)
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Result().StatusCode != http.StatusMovedPermanently {
		t.Fatalf("expected status %d, got: %d", http.StatusMovedPermanently, w.Result().StatusCode)
	}
}
