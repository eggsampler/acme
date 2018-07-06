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

func setTXT(host, value string) {
	setReq := struct {
		Host  string `json:"host"`
		Value string `json:"value"`
	}{
		Host:  host,
		Value: value,
	}
	setReqJSON, err := json.Marshal(setReq)
	if err != nil {
		panic(err)
	}
	if _, err := http.Post("http://localhost:8055/set-txt", "application/json", bytes.NewReader(setReqJSON)); err != nil {
		panic(err)
	}
}

func clearTXT(host string) {
	clearReq := struct {
		Host string `json:"host"`
	}{
		Host: host,
	}
	clearReqJSON, err := json.Marshal(clearReq)
	if err != nil {
		panic(err)
	}
	if _, err := http.Post("http://localhost:8055/clear-txt", "application/json", bytes.NewReader(clearReqJSON)); err != nil {
		panic(err)
	}
}

func TestWildcard(t *testing.T) {
	// this test uses the fake dns resolver in the boulder docker-compose setup
	randomDomain := randString() + ".com"
	domains := []string{randomDomain, "*." + randomDomain}
	var identifiers []Identifier
	for _, d := range domains {
		identifiers = append(identifiers, Identifier{"dns", d})
	}
	account, order := makeOrder(t, identifiers)

	for _, authURL := range order.Authorizations {
		currentAuth, err := testClient.FetchAuthorization(account, authURL)
		if err != nil {
			t.Fatalf("fetching auth: %v", err)
		}

		chal, ok := currentAuth.ChallengeMap[ChallengeTypeDNS01]
		if !ok {
			t.Fatal("no dns challenge provided")
		}

		host := "_acme-challenge." + currentAuth.Identifier.Value + "."
		value := EncodeDNS01KeyAuthorization(chal.KeyAuthorization)
		setTXT(host, value)
		defer clearTXT(host)

		if _, err := testClient.UpdateChallenge(account, chal); err != nil {
			t.Fatalf("error update challenge: %v", err)
		}
	}

	csr, _ := newCSR(t, domains)

	finalOrder, err := testClient.FinalizeOrder(account, order, csr)
	if err != nil {
		t.Fatalf("error finalizing: %v", err)
	}

	certs, err := testClient.FetchCertificates(finalOrder.Certificate)
	if err != nil {
		t.Fatalf("error fetch cert: %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("no certs")
	}

	cert := certs[0]
	for _, d := range domains {
		if err := cert.VerifyHostname(d); err != nil {
			t.Fatalf("error verifying hostname %s: %v", d, err)
		}
	}
}

func addTLSALPN01(token, content string) {
	addReq := struct {
		Host    string `json:"host"`
		Content string `json:"content"`
	}{
		Host:    token,
		Content: content,
	}
	addReqJSON, err := json.Marshal(addReq)
	if err != nil {
		panic(err)
	}
	if _, err := http.Post("http://localhost:8055/add-tlsalpn01", "application/json", bytes.NewReader(addReqJSON)); err != nil {
		panic(err)
	}
}

func delTLSALPN01(token string) {
	delReq := struct {
		Host string `json:"token"`
	}{
		Host: token,
	}
	delReqJSON, err := json.Marshal(delReq)
	if err != nil {
		panic(err)
	}
	if _, err := http.Post("http://localhost:8055/add-tlsalpn01", "application/json", bytes.NewReader(delReqJSON)); err != nil {
		panic(err)
	}
}

func TestClient_TLSALPN01(t *testing.T) {
	account, order := makeOrder(t, []Identifier{{Type: "dns", Value: randString() + ".com"}})

	for _, authURL := range order.Authorizations {
		currentAuth, err := testClient.FetchAuthorization(account, authURL)
		if err != nil {
			t.Fatalf("fetching auth: %v", err)
		}

		chal, ok := currentAuth.ChallengeMap[ChallengeTypeTLSALPN01]
		if !ok {
			t.Fatalf("no tls alpn 01 challenge provided: %+v", currentAuth.Challenges)
		}

		addTLSALPN01(currentAuth.Identifier.Value, chal.KeyAuthorization)
		defer delTLSALPN01(currentAuth.Identifier.Value)

		if _, err := testClient.UpdateChallenge(account, chal); err != nil {
			t.Fatalf("error update challenge: %v", err)
		}
	}

	updatedOrder, err := testClient.FetchOrder(order.URL)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if updatedOrder.Status != "ready" {
		t.Fatalf("expected ready, got: %s", updatedOrder.Status)
	}

}
