package acme

import (
	"net/http"
	"testing"
	"time"
)

func TestWithHttpTimeout(t *testing.T) {
	acmeClient := AcmeClient{httpClient: http.DefaultClient}
	timeout := 30 * time.Second
	opt := WithHttpTimeout(timeout)
	if err := opt(acmeClient); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if timeout != acmeClient.httpClient.Timeout {
		t.Fatalf("timeout not set, expected %v, got %v", timeout, acmeClient.httpClient.Timeout)
	}
}

func TestWithInsecureSkipVerify(t *testing.T) {
	acmeClient := AcmeClient{httpClient: http.DefaultClient}
	opt := WithInsecureSkipVerify()
	if err := opt(acmeClient); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tr := acmeClient.httpClient.Transport.(*http.Transport)
	if tr.TLSClientConfig.InsecureSkipVerify != true {
		t.Fatalf("InsecureSkipVerify not set")
	}
}
