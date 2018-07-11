package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	mrand "math/rand"
	"testing"
	"time"
)

type testClientType struct {
	Client
	preChallenge  func(auth Authorization, chal Challenge)
	postChallenge func(auth Authorization, chal Challenge)
}

var (
	testClient testClientType
)

func init() {
	mrand.Seed(time.Now().UnixNano())
	testClient = newBoulderClient()
	if testClient.Directory().NewAccount == "" {
		panic("error creating new client: no new account url provided")
	}
}

func randString() string {
	min := int('a')
	max := int('z')
	n := mrand.Intn(10) + 10
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = byte(mrand.Intn(max-min) + min)
	}
	return string(b)
}

func makePrivateKey(t *testing.T) crypto.Signer {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatalf("error creating account private key: %v", err)
	}
	return privKey
}

func makeAccount(t *testing.T) Account {
	key := makePrivateKey(t)
	account, err := testClient.NewAccount(key, false, true)
	if err != nil {
		t.Fatalf("error creating new account: %v", err)
	}
	return account
}

func makeOrder(t *testing.T, identifiers ...Identifier) (Account, Order) {
	if len(identifiers) == 0 {
		identifiers = []Identifier{{Type: "dns", Value: randString() + ".com"}}
	}
	account := makeAccount(t)

	order, err := testClient.NewOrder(account, identifiers)
	if err != nil {
		t.Fatalf("error making order: %v", err)
	}

	if order.Status != "pending" {
		t.Fatalf("expected pending order status, got: %s", order.Status)
	}

	if len(order.Authorizations) != len(identifiers) {
		t.Fatalf("expected %d authorizations, got: %d", len(identifiers), len(order.Authorizations))
	}
	return account, order
}

func makeOrderFinalised(t *testing.T, supportedChalTypes []string, identifiers ...Identifier) (Account, Order, crypto.Signer) {
	if len(supportedChalTypes) == 0 {
		supportedChalTypes = ValidChallenges()
	}

	acct, order := makeOrder(t, identifiers...)

	for _, authURL := range order.Authorizations {

		auth, err := testClient.FetchAuthorization(acct, authURL)
		if err != nil {
			t.Fatalf("unexpected error fetching authorization: %v", err)
		}

		chalType := supportedChalTypes[mrand.Intn(len(supportedChalTypes))]
		chal, ok := auth.ChallengeMap[chalType]
		if !ok {
			t.Fatalf("No supported challenge %q (%v) in challenges: %v", chalType, supportedChalTypes, auth.ChallengeTypes)
		}

		if chal.Status == "valid" {
			continue
		}
		if chal.Status != "pending" {
			t.Fatalf("unexpected status %q on challenge: %+v", chal.Status, chal)
		}

		testClient.preChallenge(auth, chal)

		updatedChal, err := testClient.UpdateChallenge(acct, chal)
		if err != nil {
			t.Fatalf("error updating challenge: %v", err)
		}

		testClient.postChallenge(auth, chal)

		if updatedChal.Status != "valid" {
			t.Fatalf("unexpected updated challenge status %q on challenge: %+v", updatedChal.Status, updatedChal)
		}
	}

	updatedOrder, err := testClient.FetchOrder(order.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updatedOrder.Status != "ready" {
		t.Fatal("order not ready")
	}

	var domains []string
	for _, id := range order.Identifiers {
		domains = append(domains, id.Value)
	}
	csr, privKey := newCSR(t, domains)

	finalizedOrder, err := testClient.FinalizeOrder(acct, order, csr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if finalizedOrder.Status != "valid" {
		t.Fatal("order not valid")
	}

	return acct, finalizedOrder, privKey
}

func newCSR(t *testing.T, domains []string) (*x509.CertificateRequest, crypto.Signer) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatalf("error generating private key: %v", err)
	}

	tpl := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          privKey.Public(),
		Subject:            pkix.Name{CommonName: domains[0]},
	}

	if len(domains) > 1 {
		tpl.DNSNames = append(tpl.DNSNames, domains[1:]...)
	}

	csrDer, err := x509.CreateCertificateRequest(crand.Reader, tpl, privKey)
	if err != nil {
		t.Fatalf("error generating private key: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		t.Fatalf("error generating private key: %v", err)
	}

	return csr, privKey
}
