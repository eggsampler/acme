//go:build ignore
// +build ignore

// this example tests the asynchronous order status and fetching renewal information
// has been tested using the following,
//  $ cloudflared tunnel --url http://192.168.2.178:9999
//  $ go run renewalinfo.go -domain [tunnel domain]
// output -
// Renewal info:
// - Start: 2023-06-08 00:37:21 +0000 UTC
// - End: 2023-06-10 00:37:21 +0000 UTC
// - URL:
// - Retry-After: 2023-04-10 17:17:25.6274661 +1000 AEST m=+21608.774701601

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/eggsampler/acme/v3"
)

var (
	domain  string
	keyAuth string
)

func main() {
	flag.StringVar(&domain, "domain", "",
		"domain to use for testing")
	flag.Parse()

	if domain == "" {
		panic("no domain")
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(keyAuth))
	})

	go func() {
		err := http.ListenAndServe(":9999", nil)
		ifpanic(err)
	}()

	<-time.After(2 * time.Second)

	client, err := acme.NewClient(acme.LetsEncryptStaging)
	ifpanic(err)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ifpanic(err)
	account, err := client.NewAccount(privKey, false, true, "mailto:test@eggsampler.com")
	ifpanic(err)

	order, err := client.NewOrder(account, []acme.Identifier{{Type: "dns", Value: domain}})
	ifpanic(err)

	auth, err := client.FetchAuthorization(account, order.Authorizations[0])
	ifpanic(err)
	chal, ok := auth.ChallengeMap[acme.ChallengeTypeHTTP01]
	if !ok {
		panic("no challenge")
	}
	keyAuth = chal.KeyAuthorization

	chal, err = client.UpdateChallenge(account, chal)
	ifpanic(err)

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ifpanic(err)

	tpl := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          certKey.Public(),
		Subject:            pkix.Name{CommonName: domain},
		DNSNames:           []string{domain},
	}
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, tpl, certKey)
	if err != nil {
		log.Fatalf("Error creating certificate request: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		log.Fatalf("Error parsing certificate request: %v", err)
	}

	client.IgnoreRetryAfter = true
	client.IgnorePolling = true
	order, err = client.FinalizeOrder(account, order, csr)
	ifpanic(err)
	if order.Status != "processing" {
		panic("expected async processing order")
	}

	for {
		<-time.After(time.Until(order.RetryAfter) + 5*time.Second)
		order, err = client.FetchOrder(account, order.URL)
		ifpanic(err)
		if order.Status == "valid" {
			break
		}
	}

	cert, err := client.FetchCertificates(account, order.Certificate)
	ifpanic(err)

	ri, err := client.GetRenewalInfo(cert[0], cert[1], crypto.SHA256)
	ifpanic(err)

	fmt.Println("Renewal info:")
	fmt.Printf(" - Start: %s\n", ri.SuggestedWindow.Start)
	fmt.Printf(" - End: %s\n", ri.SuggestedWindow.End)
	fmt.Printf(" - URL: %s\n", ri.ExplanationURL)
	fmt.Printf(" - Retry-After: %s\n", ri.RetryAfter)
}

func ifpanic(err error) {
	if err != nil {
		panic(err)
	}
}
