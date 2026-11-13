package acme

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// EncodeDNS01KeyAuthorization encodes a key authorization and provides a value to be put in the TXT record for the _acme-challenge DNS entry.
func EncodeDNS01KeyAuthorization(keyAuth string) string {
	h := sha256.Sum256([]byte(keyAuth))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// EncodeDNSPersist01AccountHash encodes a dns-persist-01 TXT record valid for given paramesters.
// this function doesn't use client because need to manually use fixed accounturi, which pebble randomize.
func EncodeDNSPersist01AccountHash(issuerdomain string, hashprefix string, account Account, domain string, iswild bool) string {
	dlen := uint8(len(domain))
	if dlen == 0 { // empty domain considered user opt out of the domain correlation mitigation
		dlen = 1
		domain = "*"
	}
	prehash := fmt.Sprintf("%c%s%s%s", dlen, domain, account.Thumbprint, account.URL)
	h := sha256.Sum256([]byte(prehash))
	hasheduri := fmt.Sprintf("sha-256/%s", base64.RawURLEncoding.EncodeToString(h[:]))
	if iswild {
		return fmt.Sprintf("%s; accounturi=%s%s; policy = wildcard", issuerdomain, hashprefix, hasheduri)
	}
	return fmt.Sprintf("%s; accounturi=%s%s", issuerdomain, hashprefix, hasheduri)
}

// CraftDNSPersistTxTRecord is a helper function that Crafts a dns-persist-01 TXT record string that will valid for auth's domain.
func (c Client) CraftDNSPersistTXTRecord(account Account, auth Authorization) string {
	issuerDomain := c.dir.Meta.IssuerDomainNames[0]
	hashPrefix := c.dir.Meta.AccountHashPrefix
	return EncodeDNSPersist01AccountHash(issuerDomain, hashPrefix, account, auth.Identifier.Value, auth.Wildcard)
}

// Helper function to determine whether a challenge is "finished" by its status.
func checkUpdatedChallengeStatus(challenge Challenge) (bool, error) {
	switch challenge.Status {
	case "pending":
		// Challenge objects are created in the "pending" state.
		// TODO: https://github.com/letsencrypt/boulder/issues/3346
		// return true, errors.New("acme: unexpected 'pending' challenge state")
		return false, nil

	case "processing":
		// They transition to the "processing" state when the client responds to the
		//   challenge and the server begins attempting to validate that the client has completed the challenge.
		return false, nil

	case "valid":
		// If validation is successful, the challenge moves to the "valid" state
		return true, nil

	case "invalid":
		// if there is an error, the challenge moves to the "invalid" state.
		if challenge.Error.Type != "" {
			return true, challenge.Error
		}
		return true, errors.New("acme: challenge is invalid, no error provided")

	default:
		return true, fmt.Errorf("acme: unknown challenge status: %s", challenge.Status)
	}
}

// UpdateChallenge responds to a challenge to indicate to the server to complete the challenge.
func (c Client) UpdateChallenge(account Account, challenge Challenge) (Challenge, error) {
	resp, err := c.post(challenge.URL, account.URL, account.PrivateKey, struct{}{}, &challenge, http.StatusOK)
	if err != nil {
		return challenge, err
	}

	if loc := resp.Header.Get("Location"); loc != "" {
		challenge.URL = loc
	}
	challenge.AuthorizationURL = fetchLink(resp, "up")

	if finished, err := checkUpdatedChallengeStatus(challenge); finished {
		return challenge, err
	}

	pollInterval, pollTimeout := c.getPollingDurations()
	end := time.Now().Add(pollTimeout)
	for {
		if time.Now().After(end) {
			return challenge, errors.New("acme: challenge update timeout")
		}
		time.Sleep(pollInterval)

		resp, err := c.post(challenge.URL, account.URL, account.PrivateKey, "", &challenge, http.StatusOK)
		if err != nil {
			// i don't think it's worth exiting the loop on this error
			// it could just be connectivity issue that's resolved before the timeout duration
			continue
		}

		if loc := resp.Header.Get("Location"); loc != "" {
			challenge.URL = loc
		}
		challenge.AuthorizationURL = fetchLink(resp, "up")

		if finished, err := checkUpdatedChallengeStatus(challenge); finished {
			return challenge, err
		}
	}
}

// FetchChallenge fetches an existing challenge from the given url.
func (c Client) FetchChallenge(account Account, challengeURL string) (Challenge, error) {
	challenge := Challenge{}
	resp, err := c.post(challengeURL, account.URL, account.PrivateKey, "", &challenge, http.StatusOK)
	if err != nil {
		return challenge, err
	}

	challenge.URL = resp.Header.Get("Location")
	challenge.AuthorizationURL = fetchLink(resp, "up")

	return challenge, nil
}
