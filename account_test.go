package acme

import (
	"crypto"
	"reflect"
	"strings"
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
	updatedAccount, err := testClient.UpdateAccount(account, contact...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(updatedAccount.Contact, contact) {
		t.Fatalf("contact mismatch, expected: %v, got: %v", contact, updatedAccount.Contact)
	}
}

func TestClient_UpdateAccount2(t *testing.T) {
	account := makeAccount(t)
	updatedAccount, err := testClient.UpdateAccount(Account{PrivateKey: account.PrivateKey, URL: account.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(account, updatedAccount) {
		t.Fatalf("account and updated account mismatch, expected: %+v, got: %+v", account, updatedAccount)
	}

	_, err = testClient.UpdateAccount(Account{PrivateKey: account.PrivateKey})
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

func TestClient_FetchOrderList(t *testing.T) {
	if testClientMeta.Software == clientBoulder {
		t.Skip("boulder doesnt support orders list: https://github.com/letsencrypt/boulder/issues/3335")
		return
	}

	tests := []struct {
		pre          func(acct *Account) bool
		post         func(*testing.T, Account, OrderList)
		expectsError bool
		errorStr     string
	}{
		{
			pre: func(acct *Account) bool {
				acct.Orders = ""
				return false
			},
			expectsError: true,
			errorStr:     "no order",
		},
		{
			pre: func(acct *Account) bool {
				*acct, _, _ = makeOrderFinalised(t, nil)
				return true
			},
			post: func(st *testing.T, account Account, list OrderList) {
				if len(list.Orders) != 1 {
					st.Fatalf("expected 1 orders, got: %d", len(list.Orders))
				}
			},
			expectsError: false,
		},
	}

	for i, ct := range tests {
		acct := makeAccount(t)
		if ct.pre != nil {
			update := ct.pre(&acct)
			if update {
				var err error
				acct, err = testClient.UpdateAccount(acct)
				if err != nil {
					panic(err)
				}
			}
		}
		list, err := testClient.FetchOrderList(acct)
		if ct.expectsError && err == nil {
			t.Errorf("order list test %d expected error, got none", i)
		}
		if !ct.expectsError && err != nil {
			t.Errorf("order list test %d expected no error, got: %v", i, err)
		}
		if err != nil && ct.errorStr != "" && !strings.Contains(err.Error(), ct.errorStr) {
			t.Errorf("order list test %d error doesnt contain %q: %s", i, ct.errorStr, err.Error())
		}
		if ct.post != nil {
			ct.post(t, acct, list)
		}
	}

}

/*
TODO: Create tests for this func, or migrate the tests from the old NewAccount func to this
func TestClient_NewAccountOptions(t *testing.T) {
	tests := []struct {
		name         string
		options      []NewAccountOptionFunc
		expectsError bool
		errorStr     string
	}{
		{
			name: "no hash func",
			options: []NewAccountOptionFunc{
				NewAcctOptAgreeTOS(),
			},
		},
	}

	for i, ct := range tests {
		key := makePrivateKey(t)
		_, err := testClient.NewAccountOptions(key, ct.options...)
		if ct.expectsError && err == nil {
			t.Errorf("NewAccountOptions test %d %q expected error, got none", i, ct.name)
		}
		if !ct.expectsError && err != nil {
			t.Errorf("NewAccountOptions %d %q expected no error, got: %v", i, ct.name, err)
		}
	}
}
*/
