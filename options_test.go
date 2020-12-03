package acme

import (
	"crypto"
	"net/http"
	"reflect"
	"strings"
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

func TestNewAcctOptOnlyReturnExisting(t *testing.T) {
	r := NewAccountRequest{}
	f := NewAcctOptOnlyReturnExisting()
	err := f(nil, nil, &r, Client{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !r.OnlyReturnExisting {
		t.Fatal("OnlyReturnExisting not set")
	}
}

func TestNewAcctOptAgreeTOS(t *testing.T) {
	r := NewAccountRequest{}
	f := NewAcctOptAgreeTOS()
	err := f(nil, nil, &r, Client{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !r.TermsOfServiceAgreed {
		t.Fatal("TermsOfServiceAgreed not set")
	}
}

func TestNewAcctOptWithContacts(t *testing.T) {
	r := NewAccountRequest{}
	f := NewAcctOptWithContacts("hello")
	err := f(nil, nil, &r, Client{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(r.Contact) != 1 && r.Contact[0] != "hello" {
		t.Fatalf(`expected contact "hello" got: %v`, r.Contact[0])
	}
}

func TestNewAcctOptExternalAccountBinding(t *testing.T) {
	tests := []struct {
		name         string
		binding      ExternalAccountBinding
		signer       crypto.Signer
		account      *Account
		request      *NewAccountRequest
		client       Client
		expectsError bool
		errorStr     string
	}{
		{
			name:         "empty binding",
			expectsError: true,
			errorStr:     "no KeyIdentifier set",
		},
		{
			name: "empty mac",
			binding: ExternalAccountBinding{
				KeyIdentifier: "rubbish",
			},
			expectsError: true,
			errorStr:     "no MacKey set",
		},
		{
			name: "empty algo",
			binding: ExternalAccountBinding{
				KeyIdentifier: "rubbish",
				MacKey:        "rubbish",
			},
			expectsError: true,
			errorStr:     "no Algorithm set",
		},
		{
			name: "empty hashfunc",
			binding: ExternalAccountBinding{
				KeyIdentifier: "rubbish",
				MacKey:        "rubbish",
				Algorithm:     "rubbish",
			},
			expectsError: true,
			errorStr:     "no HashFunc set",
		},
		{
			name: "unknown key type",
			binding: ExternalAccountBinding{
				KeyIdentifier: "rubbish",
				MacKey:        "rubbish",
				Algorithm:     "rubbish",
				HashFunc:      crypto.SHA256,
			},
			signer:       errSigner{},
			expectsError: true,
			errorStr:     "unknown key type",
		},
		{
			name: "invalid mac",
			binding: ExternalAccountBinding{
				KeyIdentifier: "rubbish",
				MacKey:        "!!!!",
				Algorithm:     "rubbish",
				HashFunc:      crypto.SHA256,
			},
			signer:       makePrivateKey(t),
			expectsError: true,
			errorStr:     "error decoding mac",
		},
		{
			name: "ok",
			binding: ExternalAccountBinding{
				KeyIdentifier: "rubbish",
				MacKey:        "rubbish",
				Algorithm:     "rubbish",
				HashFunc:      crypto.SHA256,
			},
			signer:  makePrivateKey(t),
			account: &Account{},
			request: &NewAccountRequest{},
		},
	}

	for i, ct := range tests {
		f := NewAcctOptExternalAccountBinding(ct.binding)
		err := f(ct.signer, ct.account, ct.request, ct.client)
		if ct.expectsError && err == nil {
			t.Errorf("decodeCertificateChain test %d %q expected error, got none", i, ct.name)
		}
		if !ct.expectsError && err != nil {
			t.Errorf("decodeCertificateChain test %d %q expected no error, got: %v", i, ct.name, err)
		}
		if err != nil && ct.errorStr != "" && !strings.Contains(err.Error(), ct.errorStr) {
			t.Errorf("AccoudecodeCertificateChainntKeyChange test %d %q error doesnt contain %q: %s", i, ct.name, ct.errorStr, err.Error())
		}
	}
}
