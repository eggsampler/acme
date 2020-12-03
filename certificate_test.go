package acme

import (
	"bytes"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
)

func Test_decodeCertificateChain(t *testing.T) {
	account, order, _ := makeOrderFinalised(t, nil)
	tests := []struct {
		name         string
		body         func() []byte
		resp         func() *http.Response
		expectsError bool
		errorStr     string
	}{
		{
			name: "invalid certificate",
			body: func() []byte {
				var b []byte
				block := &pem.Block{
					Type: "MESSAGE",
					Headers: map[string]string{
						"Animal": "Gopher",
					},
					Bytes: []byte("test"),
				}
				if err := pem.Encode(bytes.NewBuffer(b), block); err != nil {
					t.Fatal(err)
				}
				return b
			},
			resp: func() *http.Response {
				return nil
			},
		},
		{
			name: "invalid link",
			body: func() []byte {
				return nil
			},
			resp: func() *http.Response {
				return &http.Response{
					Header: map[string][]string{
						"Link": {`<http://bogus.fakedomain>; rel="up"`},
					},
				}
			},
			expectsError: true,
			errorStr:     "bogus.fakedomain",
		},
		{
			name: "valid link",
			body: func() []byte {
				return nil
			},
			resp: func() *http.Response {
				return &http.Response{
					Header: map[string][]string{
						"Link": {`<` + order.Certificate + `>; rel="up"`},
					},
				}
			},
		},
	}

	for i, ct := range tests {
		body := ct.body()
		resp := ct.resp()
		_, err := testClient.decodeCertificateChain(body, resp, account)
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

func TestClient_FetchCertificates(t *testing.T) {
	account, order, _ := makeOrderFinalised(t, nil)
	if order.Certificate == "" {
		t.Fatalf("no certificate: %+v", order)
	}
	certs, err := testClient.FetchCertificates(account, order.Certificate)
	if err != nil {
		t.Fatalf("expeceted no error, got: %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("no certs returned")
	}
	for _, d := range order.Identifiers {
		if err := certs[0].VerifyHostname(d.Value); err != nil {
			t.Fatalf("cert not verified for %s: %v - %+v", d, err, certs[0])
		}
	}
}

func TestClient_FetchAllCertificates(t *testing.T) {
	account, order, _ := makeOrderFinalised(t, nil)
	if order.Certificate == "" {
		t.Fatalf("no certificate: %+v", order)
	}
	certs, err := testClient.FetchAllCertificates(account, order.Certificate)
	if err != nil {
		t.Fatalf("expeceted no error, got: %v", err)
	}

	if len(certs) == 1 {
		t.Skip("no alternative root certificates")
	}
}

func TestClient_RevokeCertificate(t *testing.T) {
	// test revoking cert with cert key
	account, order, privKey := makeOrderFinalised(t, nil)
	if order.Certificate == "" {
		t.Fatalf("no certificate: %+v", order)
	}
	certs, err := testClient.FetchCertificates(account, order.Certificate)
	if err != nil {
		t.Fatalf("expeceted no error, got: %v", err)
	}
	if err := testClient.RevokeCertificate(account, certs[0], privKey, ReasonUnspecified); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestClient_RevokeCertificate2(t *testing.T) {
	// test revoking cert with account key
	account, order, _ := makeOrderFinalised(t, nil)
	if order.Certificate == "" {
		t.Fatalf("no certificate: %+v", order)
	}
	certs, err := testClient.FetchCertificates(account, order.Certificate)
	if err != nil {
		t.Fatalf("expeceted no error, got: %v", err)
	}
	if err := testClient.RevokeCertificate(account, certs[0], account.PrivateKey, ReasonUnspecified); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}
