package acme

import "testing"

func TestAcmeClient_FetchAuthorization(t *testing.T) {
	account, order := makeOrder(t, []AcmeIdentifier{{"dns", randString() + ".com"}})

	auth, err := testClient.FetchAuthorization(account, order.Authorizations[0])
	if err != nil {
		t.Fatalf("unexpected error fetching authorization: %v", err)
	}
	if auth.Status != "pending" {
		t.Fatalf("unexpected auth status: %s", auth.Status)
	}
	if len(auth.Challenges) == 0 {
		t.Fatalf("no challenges on auth")
	}
}

func TestAcmeClient_DeactivateAuthorization(t *testing.T) {
	account, order := makeOrder(t, []AcmeIdentifier{{"dns", randString() + ".com"}})

	auth, err := testClient.DeactivateAuthorization(account, order.Authorizations[0])
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if auth.Status != "deactivated" {
		t.Fatalf("expected deactivated status, got: %s", auth.Status)
	}
}
