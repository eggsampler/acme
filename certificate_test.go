package acme

import "testing"

func TestAcmeClient_FetchCertificate(t *testing.T) {
	domains := []string{randString() + ".com"}
	_, order, _ := makeOrderFinal(t, domains)
	if order.Certificate == "" {
		t.Fatalf("no certificate: %+v", order)
	}
	certs, err := client.FetchCertificate(order.Certificate)
	if err != nil {
		t.Fatalf("expeceted no error, got: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("wrong number of certs, expected 1, got: %d", len(certs))
	}
	for _, d := range domains {
		if err := certs[0].VerifyHostname(d); err != nil {
			t.Fatalf("cert not verified for %s: %v - %+v", d, err, certs[0])
		}
	}
}

func TestAcmeClient_FetchIssuerCertificate(t *testing.T) {
	_, err := client.FetchIssuerCertificate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAcmeClient_RevokeCertificate(t *testing.T) {
	domains := []string{randString() + ".com"}
	account, order, privKey := makeOrderFinal(t, domains)
	if order.Certificate == "" {
		t.Fatalf("no certificate: %+v", order)
	}
	certs, err := client.FetchCertificate(order.Certificate)
	if err != nil {
		t.Fatalf("expeceted no error, got: %v", err)
	}
	if err := client.RevokeCertificate(account, certs[0], privKey, ReasonUnspecified); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}
