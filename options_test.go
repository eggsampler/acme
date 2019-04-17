package acme

import (
	"net/http"
	"reflect"
	"testing"
	"time"
)

func TestWithHTTPTimeout(t *testing.T) {
	acmeClient := Client{httpClient: http.DefaultClient}
	timeout := 30 * time.Second
	opt := WithHTTPTimeout(timeout)
	if err := opt(&acmeClient); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if timeout != acmeClient.httpClient.Timeout {
		t.Fatalf("timeout not set, expected %v, got %v", timeout, acmeClient.httpClient.Timeout)
	}
}

func TestWithInsecureSkipVerify(t *testing.T) {
	acmeClient := Client{httpClient: http.DefaultClient}
	opt := WithInsecureSkipVerify()
	if err := opt(&acmeClient); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tr := acmeClient.httpClient.Transport.(*http.Transport)
	if !tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("InsecureSkipVerify not set")
	}
}

func TestWithAcceptLanguage(t *testing.T) {
	acmeClient := Client{httpClient: http.DefaultClient}
	acceptLanguage := "de"
	opt := WithAcceptLanguage(acceptLanguage)
	if err := opt(&acmeClient); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if acceptLanguage != acmeClient.acceptLanguage {
		t.Fatalf("accept language not set, expected %v, got %v", acceptLanguage, acmeClient.acceptLanguage)
	}
}

func TestWithRetryCount(t *testing.T) {
	acmeClient := Client{httpClient: http.DefaultClient}
	retryCount := 10
	opt := WithRetryCount(retryCount)
	if err := opt(&acmeClient); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if retryCount != acmeClient.retryCount {
		t.Fatalf("retry count not set, expected %v, got %v", retryCount, acmeClient.retryCount)
	}

	opt2 := WithRetryCount(-100)
	if err := opt2(&acmeClient); err == nil {
		t.Fatal("expected error, got none")
	}
}

func TestWithUserAgentSuffix(t *testing.T) {
	acmeClient := Client{httpClient: http.DefaultClient}
	suffix := "hi2u"
	opt := WithUserAgentSuffix(suffix)
	if err := opt(&acmeClient); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if suffix != acmeClient.userAgentSuffix {
		t.Fatalf("user agent suffix not set, expected %v, got %v", suffix, acmeClient.userAgentSuffix)
	}
}

func TestWithHTTPClient(t *testing.T) {
	acmeClient := Client{}
	opt1 := WithHTTPClient(nil)
	if err := opt1(&acmeClient); err == nil {
		t.Fatal("expected error, got none")
	}
	opt2 := WithHTTPClient(http.DefaultClient)
	suffix := &http.Client{}
	if err := opt2(&acmeClient); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reflect.TypeOf(suffix).Kind() != reflect.TypeOf(acmeClient.httpClient).Kind() {
		t.Fatalf("http client suffix not set, expected %v, got %v", suffix, acmeClient.httpClient)
	}
}
