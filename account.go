package acme

import (
	"net/http"

	"fmt"

	"crypto"
	"encoding/base64"

	"encoding/json"

	"crypto/ecdsa"
	"crypto/rsa"

	"gopkg.in/square/go-jose.v2"
)

// Helper function to make an account "thumbprint" used as part of authorization challenges
// https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-8.1
func makeThumbprint(key jose.SigningKey) (string, error) {
	jwkey := jose.JSONWebKey{
		Key: key.Key,
	}
	bThumbprint, err := jwkey.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("acme: error making account key thumbprint: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(bThumbprint), nil
}

// Registers a new account with the acme service
// https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-7.3
func (c AcmeClient) NewAccount(key jose.SigningKey, onlyReturnExisting, termsOfServiceAgreed bool, contact ...string) (AcmeAccount, error) {
	newAccountReq := struct {
		OnlyReturnExisting   bool     `json:"onlyReturnExisting"`
		TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
		Contact              []string `json:"contact"`
	}{
		OnlyReturnExisting:   onlyReturnExisting,
		TermsOfServiceAgreed: termsOfServiceAgreed,
		Contact:              contact,
	}

	account := AcmeAccount{}
	resp, err := c.post(c.dir.NewAccount, "", key, newAccountReq, &account, http.StatusOK, http.StatusCreated)
	if err != nil {
		return account, err
	}

	url, err := resp.Location()
	if err != nil {
		return account, fmt.Errorf("acme: error getting account location: %v", err)
	}
	account.Url = url.String()

	account.SigningKey = key

	if account.Thumbprint == "" {
		account.Thumbprint, err = makeThumbprint(account.SigningKey)
		if err != nil {
			return account, err
		}
	}

	if account.Status == "" {
		if _, err := c.post(account.Url, account.Url, key, struct{}{}, &account, http.StatusOK); err != nil {
			return account, fmt.Errorf("acme: error fetching existing account information: %v", err)
		}
	}

	return account, nil
}

// Updates an existing account with the acme service.
// https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-7.3.2
func (c AcmeClient) UpdateAccount(account AcmeAccount, termsOfServiceAgreed bool, contact ...string) (AcmeAccount, error) {
	updateAccountReq := struct {
		TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
		Contact              []string `json:"contact"`
	}{
		TermsOfServiceAgreed: termsOfServiceAgreed,
		Contact:              contact,
	}

	_, err := c.post(account.Url, account.Url, account.SigningKey, updateAccountReq, &account, http.StatusOK)
	if err != nil {
		return account, err
	}

	if account.Thumbprint == "" {
		account.Thumbprint, err = makeThumbprint(account.SigningKey)
		if err != nil {
			return account, err
		}
	}

	return account, nil
}

// Rolls over an account to a new key.
// https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-7.3.6
func (c AcmeClient) AccountKeyChange(account AcmeAccount, newKey jose.SigningKey) (AcmeAccount, error) {
	var newJwKeyPub jose.JSONWebKey
	switch k := newKey.Key.(type) {
	case *rsa.PrivateKey:
		newJwKeyPub = jose.JSONWebKey{Algorithm: "RSA", Key: k.Public()}
	case *ecdsa.PrivateKey:
		newJwKeyPub = jose.JSONWebKey{Algorithm: "ECDSA", Key: k.Public()}
	default:
		return account, fmt.Errorf("acme: unsupported private key type: %+v", k)
	}

	keyChangeReq := struct {
		Account string          `json:"account"`
		NewKey  jose.JSONWebKey `json:"newKey"`
	}{
		Account: account.Url,
		NewKey:  newJwKeyPub,
	}

	innerJws, err := encapsulateJws(nil, c.dir.KeyChange, "", newKey, keyChangeReq)
	if err != nil {
		return account, err
	}

	var b json.RawMessage
	b = []byte(innerJws.FullSerialize())

	if _, err := c.post(c.dir.KeyChange, account.Url, account.SigningKey, b, nil); err != nil {
		return account, err
	}

	return account, nil
}
