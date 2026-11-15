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

func TestEncodeDNSPersist01accounthash(t *testing.T) {
	// all example const are from https://www.ietf.org/archive/id/draft-ietf-acme-dns-persist-02.html#name-examples
	exampleAccount := Account{
		// example thumbprint from RFC7638, Section 3.1
		Thumbprint: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
		URL:        "https://ca.example/acct/123",
	}
	issuerdomain := "authority.example"
	hashprefix := "https://ca.example/account-hash/"

	tests := []struct {
		Account      Account
		domain       string
		iswild       bool
		expectedhash string
	}{
		{ // per domain record. https://www.ietf.org/archive/id/draft-ietf-acme-dns-persist-02.html#name-hashed-uri-example
			Account:      exampleAccount,
			domain:       "example.com",
			expectedhash: "authority.example; accounturi=https://ca.example/account-hash/sha-256/5SQm7n6tPh2-PlLbCKGnViTXX5z19SCN4cPGQHSk-kw",
		},

		{ // opted out of domain corelation protection
			Account:      exampleAccount,
			domain:       "", // empty domain considered for global, "" should update "*" inside
			expectedhash: "authority.example; accounturi=https://ca.example/account-hash/sha-256/NpDnSwUthQK8zCgFdefYxAdAVPnygMLbs9US6oO-5ug",
		},

		{ // test for wildcard policy
			Account:      exampleAccount,
			domain:       "example.com",
			iswild:       true,
			expectedhash: "authority.example; accounturi=https://ca.example/account-hash/sha-256/5SQm7n6tPh2-PlLbCKGnViTXX5z19SCN4cPGQHSk-kw; policy = wildcard",
		},
	}

	for _, currentTest := range tests {
		e := EncodeDNSPersist01AccountHash(issuerdomain, hashprefix, currentTest.Account, currentTest.domain, currentTest.iswild)
		if e != currentTest.expectedhash {
			t.Fatalf("expected: %s, got: %s", currentTest.expectedhash, e)
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

	preChallenge(account, auth, chal)
	defer postChallenge(account, auth, chal)

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

func Test_checkUpdatedChallengeStatus(t *testing.T) {
	tests := []struct {
		Status   string
		Finished bool
		HasError bool
	}{
		{
			Status: "pending",
		},
		{
			Status: "processing",
		},
		{
			Status:   "valid",
			Finished: true,
		},
		{
			Status:   "invalid",
			Finished: true,
			HasError: true,
		},
		{
			Status:   "blah",
			Finished: true,
			HasError: true,
		},
	}
	for _, ct := range tests {
		finished, err := checkUpdatedChallengeStatus(Challenge{
			Status: ct.Status,
		})
		if ct.Finished != finished {
			t.Fatalf("Finished mismatch on status %s, expected: %t got: %t", ct.Status, ct.Finished, finished)
		}
		if ct.HasError && err == nil {
			t.Fatalf("status %s expected error, got none", ct.Status)
		}
		if !ct.HasError && err != nil {
			t.Fatalf("status %s expected no error, got: %v", ct.Status, err)
		}
	}
}
