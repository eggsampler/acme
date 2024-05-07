package acme

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"go/build"
	"io/ioutil"
	"log"
	mrand "math/rand"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type clientMeta struct {
	Software string
	Options  []OptionFunc
}

const (
	clientBoulder = "boulder"
	clientPebble  = "pebble"
)

var (
	testClient     Client
	testClientMeta clientMeta
)

func TestMain(m *testing.M) {
	mrand.Seed(time.Now().UnixNano())
	var err error

	// attempt to use manually supplied directory url first
	if dir := os.Getenv("ACME_DIRECTORY"); dir != "" {
		var opts []OptionFunc

		if os.Getenv("ACME_STRICT") == "" {
			opts = append(opts, WithInsecureSkipVerify())
		}

		testClient, err = NewClient(dir, opts...)
		if err != nil {
			panic("error creating manual test client at '" + dir + "' - " + err.Error())
		}
		return
	}

	roots := fetchRoot()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(roots)

	directories := map[string]clientMeta{
		"https://localhost:14000/dir": {
			Software: clientPebble,
			Options:  []OptionFunc{WithRootCerts(pool)},
		},
		"https://localhost:4431/directory": {
			Software: clientBoulder,
			Options:  []OptionFunc{WithRootCerts(pool)},
		},
		"http://localhost:4001/directory": {
			Software: clientBoulder,
		},
	}

	for k, v := range directories {
		testClient, err = NewClient(k, v.Options...)
		if err != nil {
			log.Printf("error creating client for %s - %v", k, err)
			continue
		}
		testClientMeta = v

		log.Printf("using %s directory at: %s", v.Software, k)

		os.Exit(m.Run())
	}

	log.Fatal("no acme ca available")
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
			t.Skipf("skipping, no supported challenge %q (%v) in challenges: %v", chalType, supportedChalTypes, auth.ChallengeTypes)
		}

		if chal.Status == "valid" {
			continue
		}
		if chal.Status != "pending" {
			t.Fatalf("unexpected status %q on challenge: %+v", chal.Status, chal)
		}

		preChallenge(acct, auth, chal)
		defer postChallenge(acct, auth, chal)

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

func doPost(name string, req interface{}) {
	reqJSON, err := json.Marshal(req)
	if err != nil {
		panic(fmt.Sprintf("error marshalling boulder %s: %v", name, err))
	}
	if _, err := http.Post("http://localhost:8055/"+name, "application/json", bytes.NewReader(reqJSON)); err != nil {
		panic(fmt.Sprintf("error posting boulder %s: %v", name, err))
	}
}

func preChallenge(acct Account, auth Authorization, chal Challenge) {
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

	case ChallengeTypeDNSAccount01:
		acctHash := sha256.Sum256([]byte(acct.URL))
		acctLabel := strings.ToLower(base32.StdEncoding.EncodeToString(acctHash[0:10]))
		scope := "host"
		if auth.Wildcard {
			scope = "wildcard"
		}
		setReq := struct {
			Host  string `json:"host"`
			Value string `json:"value"`
		}{
			Host: "_" + acctLabel + "._acme-" + scope + "-challenge." +
				auth.Identifier.Value + ".",
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
}

func postChallenge(acct Account, auth Authorization, chal Challenge) {
	switch chal.Type {
	case ChallengeTypeDNS01:
		host := "_acme-challenge." + auth.Identifier.Value + "."
		clearReq := struct {
			Host string `json:"host"`
		}{
			Host: host,
		}
		doPost("clear-txt", clearReq)

	case ChallengeTypeDNSAccount01:
		acctHash := sha256.Sum256([]byte(acct.URL))
		acctLabel := strings.ToLower(base32.StdEncoding.EncodeToString(acctHash[0:10]))
		scope := "host"
		if auth.Wildcard {
			scope = "wildcard"
		}
		host := "_" + acctLabel + "._acme-" + scope + "-challenge." +
			auth.Identifier.Value + "."
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
}

func getPath(env, folder string) string {
	p := os.Getenv(env)
	if p != "" {
		return p
	}
	p = os.Getenv("GOPATH")
	if p != "" {
		return filepath.Join(p, "src", "github.com", "letsencrypt", folder)
	}
	p = build.Default.GOPATH
	if p != "" {
		return filepath.Join(p, "src", "github.com", "letsencrypt", folder)
	}
	p = os.Getenv("HOME")
	if p != "" {
		return filepath.Join(p, "go", "src", "github.com", "letsencrypt", folder)
	}
	return ""
}

func fetchRoot() []byte {
	var certPaths []string
	var certsPem []string

	boulderPath := getPath("BOULDER_PATH", "boulder")
	certPaths = append(certPaths, filepath.Join(boulderPath, ".hierarchy", "root-ecdsa.cert.pem"))
	certPaths = append(certPaths, filepath.Join(boulderPath, ".hierarchy", "root-cert-ecdsa.pem"))
	certPaths = append(certPaths, filepath.Join(boulderPath, ".hierarchy", "root-cert-rsa.pem"))

	certPaths = append(certPaths, filepath.Join(boulderPath, "test", "wfe-tls", "minica.pem"))

	pebblePath := getPath("PEBBLE_PATH", "pebble")
	// these certs are the ones used for the web server, not signing
	certPaths = append(certPaths, filepath.Join(pebblePath, "test", "certs", "pebble.minica.pem"))
	certPaths = append(certPaths, filepath.Join(pebblePath, "test", "certs", "localhost", "cert.pem"))

	for _, v := range certPaths {
		bPem, err := ioutil.ReadFile(v)
		if err != nil {
			log.Printf("error reading: %s - %v", v, err)
			continue
		}
		certsPem = append(certsPem, "# "+v+"\n"+strings.TrimSpace(string(bPem)))
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := &http.Client{Transport: tr}

	i := 0
	for {
		// these are the signing roots
		pebbleRootURL := fmt.Sprintf("https://localhost:15000/roots/%d", i)
		i++
		resp, err := httpClient.Get(pebbleRootURL)
		if err != nil {
			break
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			break
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			break
		}
		mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if err != nil {
			panic(err)
		}
		switch mediaType {
		case "application/pem-certificate-chain":
			certsPem = append(certsPem, strings.TrimSpace(string(body)))
		case "application/pkix-cert":
			bPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: body})
			certsPem = append(certsPem, strings.TrimSpace(string(bPem)))
		default:
			panic(pebbleRootURL + " unsupported content type: " + mediaType)
		}
	}

	if len(certsPem) == 0 {
		return nil
	}

	return []byte(strings.Join(certsPem, "\n"))
}
