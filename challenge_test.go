package acme

import "testing"

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

func makeChal(t *testing.T, identifiers []AcmeIdentifier, challengeType string) (AcmeAccount, AcmeOrder, AcmeChallenge) {
	account, order := makeOrder(t, identifiers)
	auth, err := testClient.FetchAuthorization(account, order.Authorizations[0])
	if err != nil {
		t.Fatalf("unexpected error fetching authorization: %v", err)
	}
	for _, c := range auth.Challenges {
		if c.Type == challengeType {
			return account, order, c
		}
	}
	t.Fatalf("no %s challenge: %+v", challengeType, auth.Challenges)
	return AcmeAccount{}, AcmeOrder{}, AcmeChallenge{}
}

func updateChalHttp(t *testing.T, account AcmeAccount, challenge AcmeChallenge) AcmeChallenge {
	// test challenge succeeding after error
	challengeMap.Store(challenge.Token, challenge.KeyAuthorization)
	challenge, err := testClient.UpdateChallenge(account, challenge)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if challenge.Status != "valid" {
		t.Fatalf("expected valid challenge, got: %s", challenge.Status)
	}

	return challenge
}

func TestAcmeClient_UpdateChallenge(t *testing.T) {
	account, _, chal := makeChal(t, []AcmeIdentifier{{"dns", randString() + ".com"}}, AcmeChallengeTypeHttp01)

	updateChalHttp(t, account, chal)
}

func TestAcmeClient_FetchChallenge(t *testing.T) {
	_, _, chal := makeChal(t, []AcmeIdentifier{{"dns", randString() + ".com"}}, AcmeChallengeTypeHttp01)

	fetchedChal, err := testClient.FetchChallenge(chal.Url)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if chal.Token != fetchedChal.Token {
		t.Fatalf("tokens different")
	}
}
