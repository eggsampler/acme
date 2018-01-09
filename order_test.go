package acme

import (
	"testing"

	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"
)

func TestAcmeClient_NewOrder(t *testing.T) {
	key := makePrivateKey(t)
	account, err := client.NewAccount(key, false, true)
	if err != nil {
		t.Fatalf("unexpected error making account: %v", err)
	}

	identifiers := []AcmeIdentifier{{"dns", randString() + ".com"}}
	order, err := client.NewOrder(account, identifiers)
	if err != nil {
		t.Fatalf("unexpected error making order: %v", err)
	}
	if !reflect.DeepEqual(order.Identifiers, identifiers) {
		t.Fatalf("order identifiers mismatch, identifiers: %+v, order identifiers: %+v", identifiers, order.Identifiers)
	}

	badIdentifiers := []AcmeIdentifier{{"bad", randString() + ".com"}}
	_, err = client.NewOrder(account, badIdentifiers)
	if err == nil {
		t.Fatal("expected error, got none")
	}
	if _, ok := err.(AcmeError); !ok {
		t.Fatalf("expected AcmeError, got: %v - %v", reflect.TypeOf(err), err)
	}
}

func makeOrder(t *testing.T, identifiers []AcmeIdentifier) (AcmeAccount, AcmeOrder) {
	key := makePrivateKey(t)
	account, err := client.NewAccount(key, false, true)
	if err != nil {
		t.Fatalf("unexpected error making account: %v", err)
	}

	order, err := client.NewOrder(account, identifiers)
	if err != nil {
		t.Fatalf("unexpected error making order: %v", err)
	}

	if len(order.Authorizations) != len(identifiers) {
		t.Fatalf("expected %d authorization, got: %d", len(identifiers), len(order.Authorizations))
	}

	return account, order
}

func TestAcmeClient_FetchOrder(t *testing.T) {
	if _, err := client.FetchOrder(testDirectoryUrl + "/asdasdasd"); err == nil {
		t.Fatal("expected error, got none")
	}

	_, order := makeOrder(t, []AcmeIdentifier{{"dns", randString() + ".com"}})

	fetchedOrder, err := client.FetchOrder(order.Url)
	if err != nil {
		t.Fatalf("unexpected error fetching order: %v", err)
	}

	// boulder seems to return slightly different expiry times, workaround for deepequal check
	fetchedOrder.Expires = order.Expires
	if !reflect.DeepEqual(order, fetchedOrder) {
		t.Fatalf("fetched order different to order, order: %+v, fetchedOrder: %+v", order, fetchedOrder)
	}
}

func TestAcmeClient_FetchAuthorization(t *testing.T) {
	account, order := makeOrder(t, []AcmeIdentifier{{"dns", randString() + ".com"}})

	auth, err := client.FetchAuthorization(account, order.Authorizations[0])
	if err != nil {
		t.Fatalf("unexpected error fetching authorization: %v", err)
	}

	var chal AcmeChallenge
	for _, c := range auth.Challenges {
		if c.Type == AcmeChallengeHttp01 {
			chal = c
			break
		}
	}
	if chal.Type == "" {
		t.Fatalf("no http-01 challenge found: %v", chal)
	}
	if chal.Status != "pending" {
		t.Fatalf("unexpected challenge status: %v", chal.Status)
	}
}

func makeChal(t *testing.T, identifiers []AcmeIdentifier) (AcmeAccount, AcmeOrder, AcmeChallenge) {
	account, order := makeOrder(t, identifiers)
	auth, err := client.FetchAuthorization(account, order.Authorizations[0])
	if err != nil {
		t.Fatalf("unexpected error fetching authorization: %v", err)
	}
	for _, c := range auth.Challenges {
		if c.Type == AcmeChallengeHttp01 {
			return account, order, c
		}
	}
	t.Fatalf("no http-01 challenge: %+v", auth.Challenges)
	return AcmeAccount{}, AcmeOrder{}, AcmeChallenge{}
}

func makeChalResp(t *testing.T, identifiers []AcmeIdentifier) (AcmeAccount, AcmeOrder, AcmeChallenge) {
	// this test assumes the FAKE_DNS in boulder docker-compose is set properly to connect to localhost
	account, order, chal := makeChal(t, identifiers)
	s := &http.Server{Addr: ":5002"}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(chal.KeyAuthorization))
	})
	s.Handler = mux
	go func() {
		if err := s.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				t.Fatalf("error listening: %v", err)
			}
		}
	}()
	chalResp, err := client.UpdateChallenge(account, chal)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	defer s.Shutdown(ctx)

	return account, order, chalResp
}

func TestEncodeDns01KeyAuthorization(t *testing.T) {
	tests := []struct {
		KeyAuth string
		Encoded string
	}{
		{
			"YLhavngUj1w8B79rUzxB5imUvO8DPyLDHgce89NuMfw.4fqGG7OQog-EV3ovi0b_amhdzVNWxxswDUN9ypYhWpE",
			"vKcNRAl8IQoDxFFQbEmXHgZ8O1rYk3JTFooIfYJDEEU",
		},
	}

	for _, currentTest := range tests {
		e := EncodeDns01KeyAuthorization(currentTest.KeyAuth)
		if e != currentTest.Encoded {
			t.Fatalf("expected: %s, got: %s", currentTest.Encoded, e)
		}
	}
}

func TestAcmeClient_UpdateChallenge(t *testing.T) {
	// test challenge error
	account, _, chal := makeChal(t, []AcmeIdentifier{{"dns", randString() + ".com"}})
	_, err := client.UpdateChallenge(account, chal)
	if err == nil {
		t.Fatal("expected error, got none")
	}
	acmeErr, ok := err.(AcmeError)
	if !ok {
		t.Fatalf("expected AcmeError, got: %s - %v", reflect.TypeOf(err), err)
	}
	if acmeErr.Type != "urn:ietf:params:acme:error:connection" {
		t.Fatalf("expected error urn:ietf:params:acme:error:connection, got: %v", acmeErr.Type)
	}

	// test challenge success
	makeChalResp(t, []AcmeIdentifier{{"dns", randString() + ".com"}})
}

func newCSR(t *testing.T, domains []string) (*x509.CertificateRequest, interface{}) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("error generating privte key: %v", err)
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
		t.Fatalf("error generating privte key: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		t.Fatalf("error generating privte key: %v", err)
	}

	return csr, privKey
}

func makeOrderFinal(t *testing.T, domains []string) (AcmeAccount, AcmeOrder, interface{}) {
	csr, privKey := newCSR(t, domains)

	var identifiers []AcmeIdentifier
	for _, s := range domains {
		identifiers = append(identifiers, AcmeIdentifier{"dns", s})
	}

	account, order, _ := makeChalResp(t, identifiers)
	finalOrder, err := client.FinalizeOrder(account, order, csr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return account, finalOrder, privKey
}

func TestAcmeClient_FinalizeOrder(t *testing.T) {
	makeOrderFinal(t, []string{randString() + ".com"})
}

func TestWildcard(t *testing.T) {
	// this test uses the fake dns resolver in the boulder docker-compose setup
	randomDomain := randString() + ".com"
	domains := []string{randomDomain, "*." + randomDomain}
	var identifiers []AcmeIdentifier
	for _, d := range domains {
		identifiers = append(identifiers, AcmeIdentifier{"dns", d})
	}
	account, order := makeOrder(t, identifiers)

	for _, authUrl := range order.Authorizations {
		currentAuth, err := client.FetchAuthorization(account, authUrl)
		if err != nil {
			t.Fatalf("fetching auth: %v", err)
		}

		chal, ok := currentAuth.ChallengeMap[AcmeChallengeDns01]
		if !ok {
			t.Fatal("no dns challenge provided")
		}

		setReq := fmt.Sprintf(`{"host":"%s","value":"%s"}`, "_acme-challenge."+currentAuth.Identifier.Value+".", EncodeDns01KeyAuthorization(chal.KeyAuthorization))
		if _, err := http.Post("http://localhost:8055/set-txt", "application/json", strings.NewReader(setReq)); err != nil {
			t.Fatalf("error setting txt: %v", err)
		}

		if _, err := client.UpdateChallenge(account, chal); err != nil {
			t.Fatalf("error update challenge: %v", err)
		}
	}

	csr, _ := newCSR(t, domains)

	finalOrder, err := client.FinalizeOrder(account, order, csr)
	if err != nil {
		t.Fatalf("error finalizing: %v", err)
	}

	certs, err := client.FetchCertificates(finalOrder.Certificate)
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

func TestAcmeClient_FetchOrders(t *testing.T) {
	account, _, _ := makeOrderFinal(t, []string{randString() + ".com"})
	if account.Orders == "" {
		t.Fatalf("no orders url: %+v", account)
	}
	orderList, err := client.FetchOrdersList(account.Orders)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(orderList.Orders) != 1 {
		t.Fatal("expected 1 order, got: %d", len(orderList.Orders))
	}
}
