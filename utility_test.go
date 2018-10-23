package acme

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"net/http"
	"os"
	"testing"
	"time"
)

type testClientType struct {
	Client
	server        string
	preChallenge  func(auth Authorization, chal Challenge)
	postChallenge func(auth Authorization, chal Challenge)
}

var (
	testClient testClientType
)

func init() {
	mrand.Seed(time.Now().UnixNano())
	if os.Getenv("ACME_SERVER") == "pebble" {
		testClient = newPebbleClient()
	} else {
		testClient = newBoulderClient()
	}
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
		supportedChalTypes = []string{ChallengeTypeDNS01, ChallengeTypeHTTP01}
	}

	acct, order := makeOrder(t, identifiers...)

	for _, authURL := range order.Authorizations {

		auth, err := testClient.FetchAuthorization(acct, authURL)
		if err != nil {
			t.Fatalf("unexpected error fetching authorization: %v", err)
		}

		// panic(fmt.Sprintf("AUTH: %+v\n\nORDER: %+v", auth, order))

		if auth.Status == "valid" {
			continue
		}

		if auth.Status != "pending" {
			t.Fatalf("expected auth status pending, got: %v", auth.Status)
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
		defer testClient.postChallenge(auth, chal)

		updatedChal, err := testClient.UpdateChallenge(acct, chal)
		if err != nil {
			t.Fatalf("error updating challenge %s : %v", chal.URL, err)
		}

		if updatedChal.Status != "valid" {
			t.Fatalf("unexpected updated challenge status %q on challenge: %+v", updatedChal.Status, updatedChal)
		}
	}

	updatedOrder, err := testClient.FetchOrder(acct, order.URL)
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
	csr, privKey := makeCSR(t, domains)

	finalizedOrder, err := testClient.FinalizeOrder(acct, order, csr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if finalizedOrder.Status != "valid" {
		t.Fatal("order not valid")
	}

	return acct, finalizedOrder, privKey
}

func makeCSR(t *testing.T, domains []string) (*x509.CertificateRequest, crypto.Signer) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatalf("error generating private key: %v", err)
	}

	tpl := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          privKey.Public(),
		Subject:            pkix.Name{CommonName: domains[0]},
		DNSNames:           domains,
	}

	csrDer, err := x509.CreateCertificateRequest(crand.Reader, tpl, privKey)
	if err != nil {
		t.Fatalf("error creating certificate request: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		t.Fatalf("error parsing certificate request: %v", err)
	}

	return csr, privKey
}

func newBoulderClient() testClientType {
	c, err := NewClient("http://localhost:4001/directory")
	if err != nil {
		panic("error creating boulder test client: " + err.Error())
	}
	doPost := func(name string, req interface{}) {
		reqJSON, err := json.Marshal(req)
		if err != nil {
			panic(fmt.Sprintf("error marshalling boulder %s: %v", name, err))
		}
		if _, err := http.Post("http://localhost:8055/"+name, "application/json", bytes.NewReader(reqJSON)); err != nil {
			panic(fmt.Sprintf("error posting boulder %s: %v", name, err))
		}
	}
	return testClientType{
		Client: c,
		server: "boulder",
		preChallenge: func(auth Authorization, chal Challenge) {
			switch chal.Type {
			case ChallengeTypeDNS01:
				setReq := struct {
					Host  string `json:"host"`
					Value string `json:"value"`
				}{
					Host:  "_acme-challenge." + auth.Identifier.Value + ".",
					Value: EncodeDNS01KeyAuthorization(chal.KeyAuthorization),
				}
				doPost("set-txt", setReq)

			case ChallengeTypeHTTP01:
				addReq := struct {
					Token   string `json:"token"`
					Content string `json:"content"`
				}{
					Token:   chal.Token,
					Content: chal.KeyAuthorization,
				}
				doPost("add-http01", addReq)

			case ChallengeTypeTLSALPN01:
				addReq := struct {
					Host    string `json:"host"`
					Content string `json:"content"`
				}{
					Host:    auth.Identifier.Value,
					Content: chal.KeyAuthorization,
				}
				doPost("add-tlsalpn01", addReq)

			default:
				panic("pre: unsupported challenge type: " + chal.Type)
			}
		},
		postChallenge: func(auth Authorization, chal Challenge) {
			switch chal.Type {
			case ChallengeTypeDNS01:
				host := "_acme-challenge." + auth.Identifier.Value + "."
				clearReq := struct {
					Host string `json:"host"`
				}{
					Host: host,
				}
				doPost("clear-txt", clearReq)

			case ChallengeTypeHTTP01:
				delReq := struct {
					Token string `json:"token"`
				}{
					Token: chal.Token,
				}
				doPost("del-http01", delReq)

			case ChallengeTypeTLSALPN01:
				delReq := struct {
					Host string `json:"token"`
				}{
					Host: auth.Identifier.Value,
				}
				doPost("del-tlsalpn01", delReq)

			default:
				panic("post: unsupported challenge type: " + chal.Type)
			}
		},
	}
}

func newPebbleClient() testClientType {
	c, err := NewClient("https://localhost:14000/dir", WithInsecureSkipVerify())
	if err != nil {
		panic("error creating pebble test client: " + err.Error())
	}
	return testClientType{
		Client: c,
		server: "pebble",
		preChallenge: func(auth Authorization, chal Challenge) {

		},
		postChallenge: func(auth Authorization, chal Challenge) {

		},
	}
}
