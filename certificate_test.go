package acme

import (
	"os"
	"strconv"
	"testing"
)

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
	if testClientMeta.Software == clientBoulder {
		t.Skip("boulder doesnt support alt cert chains: https://github.com/letsencrypt/boulder/issues/4567")
		return
	}
	account, order, _ := makeOrderFinalised(t, nil)
	if order.Certificate == "" {
		t.Fatalf("no certificate: %+v", order)
	}
	certs, err := testClient.FetchAllCertificates(account, order.Certificate)
	if err != nil {
		t.Fatalf("expeceted no error, got: %v", err)
	}
	roots, ok := os.LookupEnv("PEBBLE_ALTERNATE_ROOTS")
	if !ok {
		return
	}
	numRoots, err := strconv.Atoi(roots)
	if err != nil {
		panic(err)
	}
	if numRoots > 0 && len(certs) <= numRoots {
		t.Fatalf("expected > %d cert chains, got: %d", numRoots, len(certs))
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
