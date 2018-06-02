package acme

import (
	"testing"

	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"reflect"
)

func TestClient_NewOrder(t *testing.T) {
	key := makePrivateKey(t)
	account, err := testClient.NewAccount(key, false, true)
	if err != nil {
		t.Fatalf("unexpected error making account: %v", err)
	}

	identifiers := []Identifier{{"dns", randString() + ".com"}}
	order, err := testClient.NewOrder(account, identifiers)
	if err != nil {
		t.Fatalf("unexpected error making order: %v", err)
	}
	if !reflect.DeepEqual(order.Identifiers, identifiers) {
		t.Fatalf("order identifiers mismatch, identifiers: %+v, order identifiers: %+v", identifiers, order.Identifiers)
	}

	badIdentifiers := []Identifier{{"bad", randString() + ".com"}}
	_, err = testClient.NewOrder(account, badIdentifiers)
	if err == nil {
		t.Fatal("expected error, got none")
	}
	if _, ok := err.(Problem); !ok {
		t.Fatalf("expected AcmeError, got: %v - %v", reflect.TypeOf(err), err)
	}
}

func makeOrder(t *testing.T, identifiers []Identifier) (Account, Order) {
	key := makePrivateKey(t)
	account, err := testClient.NewAccount(key, false, true)
	if err != nil {
		t.Fatalf("unexpected error making account: %v", err)
	}

	order, err := testClient.NewOrder(account, identifiers)
	if err != nil {
		t.Fatalf("unexpected error making order: %v", err)
	}

	if len(order.Authorizations) != len(identifiers) {
		t.Fatalf("expected %d authorization, got: %d", len(identifiers), len(order.Authorizations))
	}

	return account, order
}

func TestClient_FetchOrder(t *testing.T) {
	if _, err := testClient.FetchOrder(testDirectoryURL + "/asdasdasd"); err == nil {
		t.Fatal("expected error, got none")
	}

	_, order := makeOrder(t, []Identifier{{"dns", randString() + ".com"}})

	fetchedOrder, err := testClient.FetchOrder(order.URL)
	if err != nil {
		t.Fatalf("unexpected error fetching order: %v", err)
	}

	// boulder seems to return slightly different expiry times, workaround for deepequal check
	fetchedOrder.Expires = order.Expires
	if !reflect.DeepEqual(order, fetchedOrder) {
		t.Fatalf("fetched order different to order, order: %+v, fetchedOrder: %+v", order, fetchedOrder)
	}
}

func newCSR(t *testing.T, domains []string) (*x509.CertificateRequest, crypto.Signer) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("error generating private key: %v", err)
	}

	tpl := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          privKey.Public(),
		Subject:            pkix.Name{CommonName: domains[0]},
		DNSNames:           []string{domains[0]},
	}

	if len(domains) > 1 {
		tpl.DNSNames = append(tpl.DNSNames, domains[1:]...)
	}

	csrDer, err := x509.CreateCertificateRequest(rand.Reader, tpl, privKey)
	if err != nil {
		t.Fatalf("error generating private key: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		t.Fatalf("error generating private key: %v", err)
	}

	return csr, privKey
}

func makeOrderFinal(t *testing.T, domains []string) (Account, Order, crypto.Signer) {
	csr, privKey := newCSR(t, domains)

	var identifiers []Identifier
	for _, s := range domains {
		identifiers = append(identifiers, Identifier{"dns", s})
	}

	account, order, chal := makeChal(t, identifiers, AcmeChallengeTypeHTTP01)
	if order.Status != "pending" {
		t.Fatalf("expected pending order status, got: %s", order.Status)
	}

	updateChalHTTP(t, account, chal)

	updatedOrder, err := testClient.FetchOrder(order.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updatedOrder.Status != "ready" {
		t.Fatal("order not ready")
	}

	finalizedOrder, err := testClient.FinalizeOrder(account, order, csr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if finalizedOrder.Status != "valid" {
		t.Fatal("order not valid")
	}

	return account, finalizedOrder, privKey
}

func TestClient_FinalizeOrder(t *testing.T) {
	makeOrderFinal(t, []string{randString() + ".com"})
}

func setTXT(host, value string) {
	setReq := struct {
		Host  string `json:"host"`
		Value string `json:"value"`
	}{
		Host:  host,
		Value: value,
	}
	setReqJSON, err := json.Marshal(setReq)
	if err != nil {
		panic(err)
	}
	if _, err := http.Post("http://localhost:8055/set-txt", "application/json", bytes.NewReader(setReqJSON)); err != nil {
		panic(err)
	}
}

func clearTXT(host string) {
	clearReq := struct {
		Host string `json:"host"`
	}{
		Host: host,
	}
	clearReqJSON, err := json.Marshal(clearReq)
	if err != nil {
		panic(err)
	}
	if _, err := http.Post("http://localhost:8055/clear-txt", "application/json", bytes.NewReader(clearReqJSON)); err != nil {
		panic(err)
	}
}

func TestWildcard(t *testing.T) {
	// this test uses the fake dns resolver in the boulder docker-compose setup
	randomDomain := randString() + ".com"
	domains := []string{randomDomain, "*." + randomDomain}
	var identifiers []Identifier
	for _, d := range domains {
		identifiers = append(identifiers, Identifier{"dns", d})
	}
	account, order := makeOrder(t, identifiers)

	for _, authURL := range order.Authorizations {
		currentAuth, err := testClient.FetchAuthorization(account, authURL)
		if err != nil {
			t.Fatalf("fetching auth: %v", err)
		}

		chal, ok := currentAuth.ChallengeMap[AcmeChallengeTypeDNS01]
		if !ok {
			t.Fatal("no dns challenge provided")
		}

		host := "_acme-challenge." + currentAuth.Identifier.Value + "."
		value := EncodeDNS01KeyAuthorization(chal.KeyAuthorization)
		setTXT(host, value)
		defer clearTXT(host)

		if _, err := testClient.UpdateChallenge(account, chal); err != nil {
			t.Fatalf("error update challenge: %v", err)
		}
	}

	csr, _ := newCSR(t, domains)

	finalOrder, err := testClient.FinalizeOrder(account, order, csr)
	if err != nil {
		t.Fatalf("error finalizing: %v", err)
	}

	certs, err := testClient.FetchCertificates(finalOrder.Certificate)
	if err != nil {
		t.Fatalf("error fetch cert: %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("no certs")
	}

	cert := certs[0]
	for _, d := range domains {
		if err := cert.VerifyHostname(d); err != nil {
			t.Fatalf("error verifying hostname %s: %v", d, err)
		}
	}
}
