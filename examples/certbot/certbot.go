package certbot

// An example of the acme library to create a simple certbot-like clone. Takes a few command line parameters and issues
// a certificate using the http-01 challenge method.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"

	"crypto/x509"
	"crypto/x509/pkix"

	"encoding/pem"

	"flag"
	"os"

	"github.com/eggsampler/acme"
)

var (
	webroot      string
	domains      string
	directoryUrl string
	contactsList string
	accountFile  string
	certFile     string
	keyFile      string
)

type acmeAccountFile struct {
	PrivateKey *ecdsa.PrivateKey `json:"privateKey"`
	Url        string            `json:"url"`
}

func main() {
	flag.StringVar(&directoryUrl, "dirurl", acme.LetsEncryptStaging,
		"acme directory url - defaults to lets encrypt v2 staging url if not provided")
	flag.StringVar(&contactsList, "contact", "",
		"a list of comma separated contact emails to use when creating a new account (optional, dont include 'mailto:' prefix)")
	flag.StringVar(&webroot, "webroot", "/var/www/html",
		"a webroot that the acme key authorization file will be written to (don't include /.acme-challenge/well-known/ suffix)")
	flag.StringVar(&domains, "domains", "",
		"a comma separated list of domains to issue a certificate for")
	flag.StringVar(&accountFile, "accountfile", "account.json",
		"the file that the account json data will be saved to/loaded from (will create new file if not exists)")
	flag.StringVar(&certFile, "certfile", "cert.pem",
		"the file that the pem encoded certificate chain will be saved to")
	flag.StringVar(&keyFile, "keyfile", "privkey.pem",
		"the file that the pem encoded certificate private key will be saved to")
	flag.Parse()

	// check domains are provided
	if domains == "" {
		log.Fatal("No domains provided")
	}
	// make sure a webroot directory exists
	if _, err := os.Stat(webroot); os.IsNotExist(err) {
		log.Fatalf("Webroot does not exist: %q", webroot)
	}

	// create a new acme client given a provided (or default) directory url
	log.Printf("Connecting to acme directory url: %s", directoryUrl)
	client, err := acme.NewClient(directoryUrl)
	if err != nil {
		log.Fatalf("Error connecting to acme directory: %v", err)
	}

	// attempt to load an existing account from file
	log.Printf("Loading account file %s", accountFile)
	account, err := loadAccount(client)
	if err != nil {
		log.Printf("Error loading existing account: %v", err)
		// if there was an error loading an account, just create a new one
		log.Printf("Creating new account")
		account, err = createAccount(client)
		if err != nil {
			log.Fatalf("Error creaing new account: %v", err)
		}
	}
	log.Printf("Account url: %s", account.URL)

	// prepend the .well-known/acme-challenge path to the webroot path
	webroot = filepath.Join(webroot, ".well-known", "acme-challenge")
	if _, err := os.Stat(webroot); os.IsNotExist(err) {
		log.Printf("Making directory path: %s", webroot)
		if err := os.MkdirAll(webroot, 0644); err != nil {
			log.Fatalf("Error creating webroot path %q: %v", webroot, err)
		}
	}

	// collect the comma separated domains into acme identifiers
	domainList := strings.Split(domains, ",")
	var ids []acme.Identifier
	for _, domain := range domainList {
		ids = append(ids, acme.Identifier{Type: "dns", Value: domain})
	}

	// create a new order with the acme service given the provided identifiers
	log.Printf("Creating new order for domains: %s", domainList)
	order, err := client.NewOrder(account, ids)
	if err != nil {
		log.Fatalf("Error creating new order: %v", err)
	}
	log.Printf("Order created: %s", order.URL)

	// loop through each of the provided authorization urls
	for _, authUrl := range order.Authorizations {
		// fetch the authorization data from the acme service given the provided authorization url
		log.Printf("Fetching authorization: %s", authUrl)
		auth, err := client.FetchAuthorization(account, authUrl)
		if err != nil {
			log.Fatalf("Error fetching authorization url %q: %v", authUrl, err)
		}
		log.Printf("Fetched authorization: %s", auth.Identifier.Value)

		// grab a http-01 challenge from the authorization if it exists
		chal, ok := auth.ChallengeMap[acme.ChallengeTypeHTTP01]
		if !ok {
			log.Fatalf("Unable to find http challenge for auth %s", auth.Identifier.Value)
		}

		// create the challenge token file with the key authorization from the challenge
		tokenFile := filepath.Join(webroot, chal.Token)
		log.Printf("Creating challenge token file: %s", tokenFile)
		defer os.Remove(tokenFile)
		if err := ioutil.WriteFile(tokenFile, []byte(chal.KeyAuthorization), 0644); err != nil {
			log.Fatalf("Error writing authorization %s challenge file %q: %v", auth.Identifier.Value, tokenFile, err)
		}

		// update the acme server that the challenge file is ready to be queried
		log.Printf("Updating challenge for authorization %s: %s", auth.Identifier.Value, chal.URL)
		chal, err = client.UpdateChallenge(account, chal)
		if err != nil {
			log.Fatalf("Error updating authorization %s challenge: %v", auth.Identifier.Value, err)
		}
		log.Printf("Challenge updated")
	}

	// all the challenges should now be completed

	// create a csr for the new certificate
	log.Printf("Generating certificate private key")
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Error generating certificate key: %v", err)
	}
	// encode the new ec private key
	certKeyEnc, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		log.Fatalf("Error encoding certificate key file: %v", err)
	}

	// write the key to the key file as a pem encoded key
	log.Printf("Writing key file: %s", keyFile)
	if err := ioutil.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: certKeyEnc,
	}), 0600); err != nil {
		log.Fatalf("Error writing key file %q: %v", keyFile, err)
	}

	// create the new csr template
	log.Printf("Creating csr")
	tpl := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          certKey.Public(),
		Subject:            pkix.Name{CommonName: domainList[0]},
		DNSNames:           domainList,
	}
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, tpl, certKey)
	if err != nil {
		log.Fatalf("Error creating certificate request: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		log.Fatalf("Error parsing certificate request: %v", err)
	}

	// finalize the order with the acme server given a csr
	log.Printf("Finalising order: %s", order.URL)
	order, err = client.FinalizeOrder(account, order, csr)
	if err != nil {
		log.Fatalf("Error finalizing order: %v", err)
	}

	// fetch the certificate chain from the finalized order provided by the acme server
	log.Printf("Fetching certificate: %s", order.Certificate)
	certs, err := client.FetchCertificates(account, order.Certificate)
	if err != nil {
		log.Fatalf("Error fetching order certificates: %v", err)
	}

	// write the pem encoded certificate chain to file
	log.Printf("Saving certificate to: %s", certFile)
	var pemData []string
	for _, c := range certs {
		pemData = append(pemData, strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		}))))
	}
	if err := ioutil.WriteFile(certFile, []byte(strings.Join(pemData, "\n")), 0600); err != nil {
		log.Fatalf("Error writing certificate file %q: %v", certFile, err)
	}

	log.Printf("Done.")
}

func loadAccount(client acme.Client) (acme.Account, error) {
	raw, err := ioutil.ReadFile(accountFile)
	if err != nil {
		return acme.Account{}, err
	}
	var accountFile acmeAccountFile
	if err := json.Unmarshal(raw, &accountFile); err != nil {
		return acme.Account{}, fmt.Errorf("error reading account file %q: %v", accountFile, err)
	}
	account, err := client.UpdateAccount(acme.Account{PrivateKey: accountFile.PrivateKey, URL: accountFile.Url}, true, getContacts()...)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error updating existing account: %v", err)
	}
	return account, nil
}

func createAccount(client acme.Client) (acme.Account, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error creating private key: %v", err)
	}
	account, err := client.NewAccount(privKey, false, true, getContacts()...)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error creating new account: %v", err)
	}
	raw, err := json.Marshal(acmeAccountFile{PrivateKey: privKey, Url: account.URL})
	if err != nil {
		return acme.Account{}, fmt.Errorf("error parsing new account: %v", err)
	}
	if err := ioutil.WriteFile(accountFile, raw, 0600); err != nil {
		return acme.Account{}, fmt.Errorf("error creating account file: %v", err)
	}
	return account, nil
}

func getContacts() []string {
	var contacts []string
	if contactsList != "" {
		contacts = strings.Split(contactsList, ",")
		for i := 0; i < len(contacts); i++ {
			contacts[i] = "mailto:" + contacts[i]
		}
	}
	return contacts
}
