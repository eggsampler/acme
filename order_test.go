package acme

import (
	"crypto/x509"
	"reflect"
	"strings"
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

func Test_checkFinalizedOrderStatus(t *testing.T) {
	tests := []struct {
		Order       Order
		Finished    bool
		HasError    bool
		ErrorString string
	}{
		{
			Order:       Order{Status: "invalid"},
			Finished:    true,
			HasError:    true,
			ErrorString: "no error provided",
		},
		{
			Order:       Order{Status: "invalid", Error: Problem{Type: "blahblahblah"}},
			Finished:    true,
			HasError:    true,
			ErrorString: "blahblahblah",
		},
		{
			Order:       Order{Status: "pending"},
			Finished:    true,
			HasError:    true,
			ErrorString: "not fulfilled",
		},
		{
			Order:       Order{Status: "ready"},
			Finished:    true,
			HasError:    true,
			ErrorString: "unexpected",
		},
		{
			Order:    Order{Status: "processing"},
			Finished: false,
			HasError: false,
		},
		{
			Order:    Order{Status: "valid"},
			Finished: true,
			HasError: false,
		},
		{
			Order:       Order{Status: "asdfasdf"},
			Finished:    true,
			HasError:    true,
			ErrorString: "unknown order status",
		},
		{
			Order:       Order{},
			HasError:    true,
			ErrorString: "unknown order status",
		},
	}

	for _, ct := range tests {
		finished, err := checkFinalizedOrderStatus(ct.Order)
		if ct.Finished != finished {
			t.Errorf("finished mismatched, expected %t, got %t", ct.Finished, finished)
		}
		if ct.HasError && err == nil {
			t.Errorf("order %v expected error, got none", ct.Order)
		}
		if !ct.HasError && err != nil {
			t.Errorf("order %v expected no error, got: %v", ct.Order, err)
		}
		if len(ct.ErrorString) > 0 {
			if err == nil {
				t.Fatalf("expected error, got none")
			}
			if !strings.Contains(err.Error(), ct.ErrorString) {
				t.Fatalf("expected error string %q not found in: %s", ct.ErrorString, err.Error())
			}
		}
	}
}

func TestClient_ReplacementOrder(t *testing.T) {
	account, order, _ := makeOrderFinalised(t, nil)
	tc2 := testClient
	tc2.dir.RenewalInfo = ""

	certs, err := tc2.FetchCertificates(account, order.Certificate)
	if err != nil {
		t.Fatalf("unexpected error fetching certificates: %v", err)
	}

	if _, err := tc2.ReplacementOrder(account, certs[0], order.Identifiers); err == nil {
		t.Fatalf("expected error, got none")
	} else if err != ErrRenewalInfoNotSupported {
		t.Fatalf("unexpected error replacing order: %v", err)
	}

	if _, err := testClient.ReplacementOrder(account, &x509.Certificate{Raw: []byte{1}}, order.Identifiers); err == nil {
		t.Fatalf("expected error, got none")
	}

	newOrder, err := testClient.ReplacementOrder(account, certs[0], order.Identifiers)
	if err != nil {
		t.Fatalf("unexpected error replacing certificates: %v", err)
	}
	if !reflect.DeepEqual(newOrder.Identifiers, order.Identifiers) {
		t.Fatalf("unexpected difference in replaced order identifiers")
	}
	if newOrder.Replaces == "" {
		t.Fatalf("replace order identifier is empty")
	}
}
