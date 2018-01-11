package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"reflect"
)

func makePrivateKey(t *testing.T) interface{} {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("error creating account private key: %v", err)
	}
	return privKey
}

func TestAcmeClient_NewAccount(t *testing.T) {
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
		acmeErr, ok := err.(AcmeError)
		if !ok {
			t.Fatalf("unknown error %s: %v", currentTest.Name, err)
		}
		if acmeErr.Type == "" {
			t.Fatalf("%s no acme error type present: %+v", currentTest.Name, acmeErr)
		}
	}

	successTests := []struct {
		Name    string
		Contact []string
	}{
		{
			Name: "new account without contact",
		},
		{
			Name:    "new account with contact",
			Contact: []string{"mailto:test@test.com"},
		},
	}
	for _, currentTest := range successTests {
		key := makePrivateKey(t)
		if _, err := testClient.NewAccount(key, false, true, currentTest.Contact...); err != nil {
			t.Fatalf("unexpected error %s: %v", currentTest.Name, err)
		}
	}

	// test making a new account
	key := makePrivateKey(t)
	newAccount, err := testClient.NewAccount(key, false, true)
	if err != nil {
		t.Fatalf("unexpected error making new account: %v", err)
	}

	// test fetching an existing account
	existingAccount, err := testClient.NewAccount(key, true, true)
	if err != nil {
		t.Fatalf("unexpected error fetching existing account: %v", err)
	}
	if !reflect.DeepEqual(newAccount, existingAccount) {
		t.Fatalf("accounts are different")
	}

	// test updating an account
	contact := []string{"mailto:test@test.com"}
	updatedAccount, err := testClient.UpdateAccount(existingAccount, true, contact...)
	if err != nil {
		t.Fatalf("unexpected error updating account: %v", err)
	}
	if !reflect.DeepEqual(updatedAccount.Contact, contact) {
		t.Fatalf("error updating account, contacts dont match, expected %v, got: %v", contact, updatedAccount.Contact)
	}
}

func TestAcmeClient_UpdateAccount(t *testing.T) {
	key := makePrivateKey(t)
	account, err := testClient.NewAccount(key, false, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	contact := []string{"mailto:test@test.com"}
	updatedAccount, err := testClient.UpdateAccount(account, true, contact...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(updatedAccount.Contact, contact) {
		t.Fatalf("contact mismatch, expected: %v, got: %v", contact, updatedAccount.Contact)
	}
}

func TestAcmeClient_AccountKeyChange(t *testing.T) {
	key := makePrivateKey(t)
	account, err := testClient.NewAccount(key, false, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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

func TestAcmeClient_DeactivateAccount(t *testing.T) {
	key := makePrivateKey(t)
	account, err := testClient.NewAccount(key, false, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	account, err = testClient.DeactivateAccount(account)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if account.Status != "deactivated" {
		t.Fatalf("expected account deactivated, got: %s", account.Status)
	}
}
