package acme

import (
	"reflect"
	"strings"
	"testing"
)

func TestDomainsToIds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                string
		domains             []string
		expectedIdentifiers []Identifier
		expectedFailure     bool
	}{
		{
			name:            "No domains",
			domains:         nil,
			expectedFailure: true,
		},
		{
			name:                "One domain",
			domains:             []string{"example.com"},
			expectedIdentifiers: []Identifier{{"dns", "example.com"}},
		},
		{
			name:                "Multiple domains",
			domains:             []string{"example.org", "example.net"},
			expectedIdentifiers: []Identifier{{"dns", "example.org"}, {"dns", "example.net"}},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ids, err := domainsToIds(tc.domains)
			if !tc.expectedFailure {
				if err != nil {
					t.Fatal(err)
				}
			}
			if len(ids) != len(tc.expectedIdentifiers) {
				t.Fatalf("unexpected amount of IDs: %d != %d", len(ids), len(tc.expectedIdentifiers))
			}
			if !reflect.DeepEqual(ids, tc.expectedIdentifiers) {
				t.Fatalf("unexpected error: %v != %v", ids, tc.expectedIdentifiers)
			}
		})
	}
}

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

func TestClient_NewOrderDomains(t *testing.T) {
	account := makeAccount(t)
	_, err := testClient.NewOrderDomains(account)
	if err == nil {
		t.Fatalf("expected error, got none")
	}
}

func Test_checkFinalizedOrderStatus(t *testing.T) {
	tests := []struct {
		Order       *Order
		Finished    bool
		HasError    bool
		ErrorString string
	}{
		{
			Order:       &Order{Status: "invalid"},
			Finished:    true,
			HasError:    true,
			ErrorString: "no error provided",
		},
		{
			Order:       &Order{Status: "invalid", Error: Problem{Type: "blahblahblah"}},
			Finished:    true,
			HasError:    true,
			ErrorString: "blahblahblah",
		},
		{
			Order:       &Order{Status: "pending"},
			Finished:    true,
			HasError:    true,
			ErrorString: "not fulfilled",
		},
		{
			Order:       &Order{Status: "ready"},
			Finished:    true,
			HasError:    true,
			ErrorString: "unexpected",
		},
		{
			Order:    &Order{Status: "processing"},
			Finished: false,
			HasError: false,
		},
		{
			Order:    &Order{Status: "valid"},
			Finished: true,
			HasError: false,
		},
		{
			Order:       &Order{Status: "asdfasdf"},
			Finished:    true,
			HasError:    true,
			ErrorString: "unknown order status",
		},
		{
			Order:       nil,
			HasError:    true,
			ErrorString: "nil order",
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
