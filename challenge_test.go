package acme

import (
	"testing"
)

func TestEncodeDns01KeyAuthorization(t *testing.T) {
	tests := []struct {
		KeyAuth string
		Encoded string
	}{
		{
			"YLhavngUj1w8B79rUzxB5imUvO8DPyLDHgce89NuMfw.4fqGG7OQog-EV3ovi0b_amhdzVNWxxswDUN9ypYhWpE",
			"vKcNRAl8IQoDxFFQbEmXHgZ8O1rYk3JTFooIfYJDEEU",
		},
	}

	for _, currentTest := range tests {
		e := EncodeDNS01KeyAuthorization(currentTest.KeyAuth)
		if e != currentTest.Encoded {
			t.Fatalf("expected: %s, got: %s", currentTest.Encoded, e)
		}
	}
}

func TestClient_UpdateChallenge(t *testing.T) {
	account, order := makeOrder(t)
	auth, err := testClient.FetchAuthorization(account, order.Authorizations[0])
	if err != nil {
		t.Fatalf("unexpected error fetching authorization: %v", err)
	}

	chal := auth.ChallengeMap[ChallengeTypeDNS01]

	testClient.preChallenge(auth, chal)
	defer testClient.postChallenge(auth, chal)

	updatedChal, err := testClient.UpdateChallenge(account, chal)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if updatedChal.Status != "valid" {
		t.Fatalf("expected valid challenge, got: %s", chal.Status)
	}
}

func TestClient_FetchChallenge(t *testing.T) {
	account, order := makeOrder(t)
	auth, err := testClient.FetchAuthorization(account, order.Authorizations[0])
	if err != nil {
		t.Fatalf("unexpected error fetching authorization: %v", err)
	}

	chal := auth.Challenges[0]

	fetchedChal, err := testClient.FetchChallenge(account, chal.URL)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if chal.Token != fetchedChal.Token {
		t.Fatalf("tokens different")
	}
}
