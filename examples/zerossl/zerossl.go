//build +ignore
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/eggsampler/acme/v3"
)

type acmeAccountFile struct {
	PrivateKey string `json:"privateKey"`
	Url        string `json:"url"`
	EABKID     string `json:"eab_kid"`
	EABMAC     string `json:"eab_mac"`
	EABAlgo    string `json:"eab_algo"`
}

const accountFile = "account.json"

func main() {
	client, err := acme.NewClient("https://acme.zerossl.com/v2/DV90")
	iferr(err, "creating client")

	if !client.Directory().Meta.ExternalAccountRequired {
		log.Fatalf("Expected ExternalAccountRequired")
	}

	account, err := loadAccount(client)
	if err != nil {
		account = createAccount(client)
	}

	log.Printf("account: %+v", account)

	orders, err := client.FetchOrderList(account)
	iferr(err, "fetching order list")
	for _, v := range orders.Orders {
		log.Printf("Order: %+v", v)
	}
}

func loadAccount(client acme.Client) (acme.Account, error) {
	raw, err := ioutil.ReadFile(accountFile)
	if err != nil {
		return acme.Account{}, err
	}
	var aaf acmeAccountFile
	if err := json.Unmarshal(raw, &aaf); err != nil {
		return acme.Account{}, err
	}
	account, err := client.UpdateAccount(acme.Account{PrivateKey: pem2key([]byte(aaf.PrivateKey)), URL: aaf.Url})
	if err != nil {
		return acme.Account{}, err
	}
	return account, nil
}

func createAccount(client acme.Client) acme.Account {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	iferr(err, "generating priv key")

	// TODO: Enter EAB Credentials as generated at https://app.zerossl.com/developer

	algo := os.Getenv("EAB_ALGO")
	if algo == "" {
		algo = "SHA-256"
	}
	var hf crypto.Hash
	switch algo {
	case "SHA-256":
		hf = crypto.SHA256
	case "SHA-384":
		hf = crypto.SHA384
	case "SHA-512":
		hf = crypto.SHA512
	default:
		log.Fatalf("Unsupported hash function: %s", algo)
	}
	eab := acme.ExternalAccountBinding{
		KeyIdentifier: os.Getenv("EAB_KID"),
		MacKey:        os.Getenv("EAB_HMAC_Key"),
		HashFunc:      hf,
	}

	log.Printf("EAB: %+v", eab)

	account, err := client.NewAccountExternalBinding(privKey, false, true, eab)
	iferr(err, "creating new account")
	acc := acmeAccountFile{
		PrivateKey: string(key2pem(privKey)),
		Url:        account.URL,
		EABKID:     eab.KeyIdentifier,
		EABMAC:     eab.MacKey,
		EABAlgo:    fmt.Sprintf("%s", eab.HashFunc),
	}
	raw, err := json.Marshal(acc)
	iferr(err, "marshalling acc")
	err = ioutil.WriteFile(accountFile, raw, 0600)
	iferr(err, "writing account file")
	return account
}

func key2pem(certKey *ecdsa.PrivateKey) []byte {
	certKeyEnc, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		log.Fatalf("Error encoding key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: certKeyEnc,
	})
}

func pem2key(data []byte) *ecdsa.PrivateKey {
	b, _ := pem.Decode(data)
	key, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		log.Fatalf("Error decoding key: %v", err)
	}
	return key
}

func iferr(err error, s string) {
	if err != nil {
		log.Fatalf("%s: %v", s, err)
	}
}
