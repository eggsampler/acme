package acme

import (
	"net/http"

	"fmt"

	"crypto"
	"encoding/json"
)

// NewAccount registers a new account with the acme service
// More details: https://tools.ietf.org/html/draft-ietf-acme-acme-10#section-7.3
func (c AcmeClient) NewAccount(privateKey crypto.Signer, onlyReturnExisting, termsOfServiceAgreed bool, contact ...string) (AcmeAccount, error) {
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
		account.Thumbprint, err = JWKThumbprint(account.PrivateKey.Public())
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

// UpdateAccount updates an existing account with the acme service.
// More details: https://tools.ietf.org/html/draft-ietf-acme-acme-10#section-7.3.2
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
		account.Thumbprint, err = JWKThumbprint(account.PrivateKey.Public())
		if err != nil {
			return account, err
		}
	}

	return account, nil
}

// AccountKeyChange rolls over an account to a new key.
// More details: https://tools.ietf.org/html/draft-ietf-acme-acme-10#section-7.3.6
func (c AcmeClient) AccountKeyChange(account AcmeAccount, newPrivateKey crypto.Signer) (AcmeAccount, error) {
	newJwkKeyPub, err := jwkEncode(newPrivateKey.Public())
	if err != nil {
		return account, fmt.Errorf("acme: error encoding new private key: %v", err)
	}

	keyChangeReq := struct {
		Account string          `json:"account"`
		NewKey  json.RawMessage `json:"newKey"`
	}{
		Account: account.Url,
		NewKey:  []byte(newJwkKeyPub),
	}

	innerJws, err := jwsEncodeJSON(keyChangeReq, newPrivateKey, c.Directory.KeyChange, "", "")
	if err != nil {
		return account, fmt.Errorf("acme: error encoding inner jws: %v", err)
	}

	if _, err := c.post(c.Directory.KeyChange, account.Url, account.PrivateKey, json.RawMessage(innerJws), nil, http.StatusOK); err != nil {
		return account, err
	}

	account.PrivateKey = newPrivateKey

	return account, nil
}

// DeactivateAccount deactivates a given account.
// More details: https://tools.ietf.org/html/draft-ietf-acme-acme-10#section-7.3.7
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
