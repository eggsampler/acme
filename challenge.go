package acme

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Encodes a key authorization and provides a value to be put in the TXT record for the _acme-challenge DNS entry.
// https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-8.5
func EncodeDns01KeyAuthorization(keyAuth string) string {
	h := sha256.New()
	h.Write([]byte(keyAuth))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// Helper function to determine whether a challenge is "finished" by it's status.
func checkChallengeStatus(challenge AcmeChallenge) (bool, error) {
	switch challenge.Status {
	case "valid":
		return true, nil
	case "invalid":
		if challenge.Error.Type != "" {
			return true, challenge.Error
		}
		return true, errors.New("acme: challenge is invalid, no error provided")
	case "pending":
		return false, nil
	default:
		return true, fmt.Errorf("acme: unknown challenge status: %s", challenge.Status)
	}
}

// Responds to a challenge to indicate to the server to complete the challenge.
// https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-7.5.1
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

	if finished, err := checkChallengeStatus(challenge); finished {
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

		if finished, err := checkChallengeStatus(challenge); finished {
			return challenge, err
		}
	}
}

// Fetches an existing challenge from the given url.
func (c AcmeClient) FetchChallenge(challengeUrl string) (AcmeChallenge, error) {
	challenge := AcmeChallenge{}
	resp, err := c.get(challengeUrl, &challenge, http.StatusOK)
	if err != nil {
		return challenge, err
	}

	challenge.Url = resp.Header.Get("Location")
	challenge.AuthorizationUrl = fetchLink(resp, "up")

	return challenge, nil
}
