package acme

import "testing"

func TestWildcard(t *testing.T) {
	d := "*." + randString() + ".com"
	_, order, _ := makeOrderFinalised(t, []string{ChallengeTypeDNS01}, Identifier{Type: "dns", Value: d})

	certs, err := testClient.FetchCertificates(order.Certificate)
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
