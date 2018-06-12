package acme

import (
	"bytes"
	"encoding/json"
	"net/http"
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

func makeChal(t *testing.T, identifiers []Identifier, challengeType string) (Account, Order, Challenge) {
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
	return Account{}, Order{}, Challenge{}
}

func addHTTP01(token, content string) {
	addReq := struct {
		Token   string `json:"token"`
		Content string `json:"content"`
	}{
		Token:   token,
		Content: content,
	}
	addReqJSON, err := json.Marshal(addReq)
	if err != nil {
		panic(err)
	}
	if _, err := http.Post("http://localhost:8055/add-http01", "application/json", bytes.NewReader(addReqJSON)); err != nil {
		panic(err)
	}
}

func delHTTP01(token string) {
	delReq := struct {
		Token string `json:"token"`
	}{
		Token: token,
	}
	delReqJSON, err := json.Marshal(delReq)
	if err != nil {
		panic(err)
	}
	if _, err := http.Post("http://localhost:8055/add-http01", "application/json", bytes.NewReader(delReqJSON)); err != nil {
		panic(err)
	}
}

func updateChalHTTP(t *testing.T, account Account, challenge Challenge) Challenge {
	// test challenge succeeding after error
	addHTTP01(challenge.Token, challenge.KeyAuthorization)
	defer delHTTP01(challenge.Token)
	challenge, err := testClient.UpdateChallenge(account, challenge)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if challenge.Status != "valid" {
		t.Fatalf("expected valid challenge, got: %s", challenge.Status)
	}

	return challenge
}

func TestClient_UpdateChallenge(t *testing.T) {
	account, _, chal := makeChal(t, []Identifier{{"dns", randString() + ".com"}}, ChallengeTypeHTTP01)

	updateChalHTTP(t, account, chal)
}

func TestClient_FetchChallenge(t *testing.T) {
	_, _, chal := makeChal(t, []Identifier{{"dns", randString() + ".com"}}, ChallengeTypeHTTP01)

	fetchedChal, err := testClient.FetchChallenge(chal.URL)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if chal.Token != fetchedChal.Token {
		t.Fatalf("tokens different")
	}
}
