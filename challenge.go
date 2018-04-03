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
// More details: https://tools.ietf.org/html/draft-ietf-acme-acme-10#section-8.4
func EncodeDNS01KeyAuthorization(keyAuth string) string {
	h := sha256.New()
	h.Write([]byte(keyAuth))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// Helper function to determine whether a challenge is "finished" by it's status.
func checkUpdatedChallengeStatus(challenge AcmeChallenge) (bool, error) {
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
// More details: https://tools.ietf.org/html/draft-ietf-acme-acme-10#section-7.5.1
func (c AcmeClient) UpdateChallenge(account AcmeAccount, challenge AcmeChallenge) (AcmeChallenge, error) {
	chalReq := struct {
		KeyAuthorization string `json:"keyAuthorization"`
	}{
		KeyAuthorization: challenge.KeyAuthorization,
	}

	resp, err := c.post(challenge.Url, account.Url, account.PrivateKey, chalReq, &challenge, http.StatusOK)
	if err != nil {
		return challenge, err
	}

	challenge.Url = resp.Header.Get("Location")
	challenge.AuthorizationUrl = fetchLink(resp, "up")

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

		resp, err := c.get(challenge.Url, &challenge, http.StatusOK)
		if err != nil {
			// i dont think it's worth exiting the loop on this error
			// it could just be connectivity issue thats resolved before the timeout duration
			continue
		}

		challenge.Url = resp.Header.Get("Location")
		challenge.AuthorizationUrl = fetchLink(resp, "up")

		if finished, err := checkUpdatedChallengeStatus(challenge); finished {
			return challenge, err
		}
	}
}

// FetchChallenge fetches an existing challenge from the given url.
func (c AcmeClient) FetchChallenge(challengeURL string) (AcmeChallenge, error) {
	challenge := AcmeChallenge{}
	resp, err := c.get(challengeURL, &challenge, http.StatusOK)
	if err != nil {
		return challenge, err
	}

	challenge.Url = resp.Header.Get("Location")
	challenge.AuthorizationUrl = fetchLink(resp, "up")

	return challenge, nil
}
