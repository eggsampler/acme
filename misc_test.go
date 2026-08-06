package acme

import "testing"

func TestWildcard(t *testing.T) {
	d := "*." + randString() + ".com"
	account, order, _ := makeOrderFinalised(t, []string{ChallengeTypeDNS01}, Identifier{Type: "dns", Value: d})

	certs, err := testClient.FetchCertificates(account, order.Certificate)
	if err != nil {
		t.Fatalf("error fetch cert: %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("no certs")
	}

	if err := certs[0].VerifyHostname(d); err != nil {
		t.Fatalf("error verifying hostname %s: %v", d, err)
	}
}

func TestWildcardDNSAccount(t *testing.T) {
	if testClientMeta.Software == clientBoulder {
		// boulder derives the dns-account-01 label from the first entry in its
		// configured accountURIPrefixes (boulder.service.consul:4001 in the
		// test config) rather than from the account url it issued to us
		// (localhost:4001), so the label we compute never matches the one it
		// queries. see validateDNSAccount01 in boulder's va/dns.go.
		t.Skip("boulder derives the dns-account-01 label from a different account url")
	}

	d := "*." + randString() + ".com"
	account, order, _ := makeOrderFinalised(t, []string{ChallengeTypeDNSAccount01}, Identifier{Type: "dns", Value: d})

	certs, err := testClient.FetchCertificates(account, order.Certificate)
	if err != nil {
		t.Fatalf("error fetch cert: %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("no certs")
	}

	if err := certs[0].VerifyHostname(d); err != nil {
		t.Fatalf("error verifying hostname %s: %v", d, err)
	}
}
