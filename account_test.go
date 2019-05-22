package acme

import (
	"crypto"
	"reflect"
	"testing"
)

func TestClient_NewAccount(t *testing.T) {
	errorTests := []struct {
		Name                 string
		OnlyReturnExisting   bool
		TermsOfServiceAgreed bool
		Contact              []string
	}{
		{
			Name:                 "fetching non-existing account",
			OnlyReturnExisting:   true,
			TermsOfServiceAgreed: true,
		},
		{
			Name:                 "not agreeing to terms of service",
			OnlyReturnExisting:   false,
			TermsOfServiceAgreed: false,
		},
		{
			Name:                 "bad contacts",
			OnlyReturnExisting:   false,
			TermsOfServiceAgreed: true,
			Contact:              []string{"this will fail"},
		},
	}
	for _, currentTest := range errorTests {
		key := makePrivateKey(t)
		_, err := testClient.NewAccount(key, currentTest.OnlyReturnExisting, currentTest.TermsOfServiceAgreed, currentTest.Contact...)
		if err == nil {
			t.Fatalf("expected error %s, got none", currentTest.Name)
		}
		acmeErr, ok := err.(Problem)
		if !ok {
			t.Fatalf("unknown error %s: %v", currentTest.Name, err)
		}
		if acmeErr.Type == "" {
			t.Fatalf("%s no acme error type present: %+v", currentTest.Name, acmeErr)
		}
	}
}

func TestClient_NewAccount2(t *testing.T) {
	existingKey := makePrivateKey(t)
	successTests := []struct {
		Name     string
		Existing bool
		Key      crypto.Signer
		Contact  []string
	}{
		{
			Name: "new account without contact",
		},
		{
			Name:    "new account with contact",
			Contact: []string{"mailto:test@test.com"},
		},
		{
			Name: "new account for fetching existing",
			Key:  existingKey,
		},
		{
			Name:     "fetching existing account",
			Key:      existingKey,
			Existing: true,
		},
	}
	for _, currentTest := range successTests {
		var key crypto.Signer
		if currentTest.Key != nil {
			key = currentTest.Key
		} else {
			key = makePrivateKey(t)
		}
		if _, err := testClient.NewAccount(key, currentTest.Existing, true, currentTest.Contact...); err != nil {
			t.Fatalf("unexpected error %s: %v", currentTest.Name, err)
		}
	}
}

func TestClient_UpdateAccount(t *testing.T) {
	account := makeAccount(t)
	contact := []string{"mailto:test@test.com"}
	updatedAccount, err := testClient.UpdateAccount(account, true, contact...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(updatedAccount.Contact, contact) {
		t.Fatalf("contact mismatch, expected: %v, got: %v", contact, updatedAccount.Contact)
	}
}

func TestClient_UpdateAccount2(t *testing.T) {
	account := makeAccount(t)
	updatedAccount, err := testClient.UpdateAccount(Account{PrivateKey: account.PrivateKey, URL: account.URL}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(account, updatedAccount) {
		t.Fatalf("account and updated account mismatch, expected: %+v, got: %+v", account, updatedAccount)
	}

	_, err = testClient.UpdateAccount(Account{PrivateKey: account.PrivateKey}, true)
	if err == nil {
		t.Fatalf("expected error, got none")
	}
}

func TestClient_AccountKeyChange(t *testing.T) {
	account := makeAccount(t)
	newKey := makePrivateKey(t)
	accountNewKey, err := testClient.AccountKeyChange(account, newKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if accountNewKey.PrivateKey == account.PrivateKey {
		t.Fatal("account key didnt change")
	}

	if accountNewKey.PrivateKey != newKey {
		t.Fatal("new key isnt set")
	}
}

func TestClient_DeactivateAccount(t *testing.T) {
	account := makeAccount(t)
	var err error
	account, err = testClient.DeactivateAccount(account)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if account.Status != "deactivated" {
		t.Fatalf("expected account deactivated, got: %s", account.Status)
	}
}
