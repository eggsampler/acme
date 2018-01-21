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
// More details: https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-8.1
func makeThumbprint(privateKey interface{}) (string, error) {
	jwk := jose.JSONWebKey{Key: privateKey}
	bThumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("acme: error making account key thumbprint: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(bThumbprint), nil
}

// Registers a new account with the acme service
// More details: https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-7.3
func (c AcmeClient) NewAccount(privateKey interface{}, onlyReturnExisting, termsOfServiceAgreed bool, contact ...string) (AcmeAccount, error) {
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
	resp, err := c.post(c.Directory.NewAccount, "", privateKey, newAccountReq, &account, http.StatusOK, http.StatusCreated)
	if err != nil {
		return account, err
	}

	account.Url = resp.Header.Get("Location")
	account.PrivateKey = privateKey

	if account.Thumbprint == "" {
		account.Thumbprint, err = makeThumbprint(account.PrivateKey)
		if err != nil {
			return account, err
		}
	}

	if account.Status == "" {
		if _, err := c.post(account.Url, account.Url, privateKey, struct{}{}, &account, http.StatusOK); err != nil {
			return account, fmt.Errorf("acme: error fetching existing account information: %v", err)
		}
	}

	return account, nil
}

// Updates an existing account with the acme service.
// More details: https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-7.3.2
func (c AcmeClient) UpdateAccount(account AcmeAccount, termsOfServiceAgreed bool, contact ...string) (AcmeAccount, error) {
	updateAccountReq := struct {
		TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
		Contact              []string `json:"contact"`
	}{
		TermsOfServiceAgreed: termsOfServiceAgreed,
		Contact:              contact,
	}

	_, err := c.post(account.Url, account.Url, account.PrivateKey, updateAccountReq, &account, http.StatusOK)
	if err != nil {
		return account, err
	}

	if account.Thumbprint == "" {
		account.Thumbprint, err = makeThumbprint(account.PrivateKey)
		if err != nil {
			return account, err
		}
	}

	return account, nil
}

// Rolls over an account to a new key.
// More details: https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-7.3.6
func (c AcmeClient) AccountKeyChange(account AcmeAccount, newPrivateKey interface{}) (AcmeAccount, error) {
	var newJwKeyPub jose.JSONWebKey
	switch k := newPrivateKey.(type) {
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

	innerJws, err := encapsulateJws(nil, c.Directory.KeyChange, "", newPrivateKey, keyChangeReq)
	if err != nil {
		return account, err
	}

	var b json.RawMessage
	b = []byte(innerJws.FullSerialize())

	if _, err := c.post(c.Directory.KeyChange, account.Url, account.PrivateKey, b, nil, http.StatusOK); err != nil {
		return account, err
	}

	account.PrivateKey = newPrivateKey

	return account, nil
}

// Deactivates a given account.
// More details: https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-7.3.7
func (c AcmeClient) DeactivateAccount(account AcmeAccount) (AcmeAccount, error) {
	deactivateReq := struct {
		Status string `json:"status"`
	}{
		Status: "deactivated",
	}

	_, err := c.post(account.Url, account.Url, account.PrivateKey, deactivateReq, &account, http.StatusOK)
	if err != nil {
		return account, err
	}

	return account, nil
}
