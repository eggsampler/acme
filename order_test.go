package acme

import (
	"reflect"
	"testing"
)

func TestClient_NewOrder(t *testing.T) {
	key := makePrivateKey(t)
	account, err := testClient.NewAccount(key, false, true)
	if err != nil {
		t.Fatalf("unexpected error making account: %v", err)
	}

	identifiers := []Identifier{{"dns", randString() + ".com"}}
	order, err := testClient.NewOrder(account, identifiers)
	if err != nil {
		t.Fatalf("unexpected error making order: %v", err)
	}
	if !reflect.DeepEqual(order.Identifiers, identifiers) {
		t.Fatalf("order identifiers mismatch, identifiers: %+v, order identifiers: %+v", identifiers, order.Identifiers)
	}

	badIdentifiers := []Identifier{{"bad", randString() + ".com"}}
	_, err = testClient.NewOrder(account, badIdentifiers)
	if err == nil {
		t.Fatal("expected error, got none")
	}
	if _, ok := err.(Problem); !ok {
		t.Fatalf("expected Problem, got: %v - %v", reflect.TypeOf(err), err)
	}
}

func TestClient_FetchOrder(t *testing.T) {
	account, order := makeOrder(t)

	if _, err := testClient.FetchOrder(account, testClient.Directory().URL+"/asdasdasd"); err == nil {
		t.Fatal("expected error, got none")
	}

	fetchedOrder, err := testClient.FetchOrder(account, order.URL)
	if err != nil {
		t.Fatalf("unexpected error fetching order: %v", err)
	}

	// boulder seems to return slightly different expiry times, workaround for deepequal check
	fetchedOrder.Expires = order.Expires
	if !reflect.DeepEqual(order, fetchedOrder) {
		t.Fatalf("fetched order different to order, order: %+v, fetchedOrder: %+v", order, fetchedOrder)
	}
}

func TestClient_FinalizeOrder(t *testing.T) {
	makeOrderFinalised(t, nil)
}
