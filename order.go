package acme

import (
	"net/http"

	"encoding/base64"

	"fmt"

	"time"

	"errors"

	"crypto/x509"

	"crypto/sha256"
)

func (c AcmeClient) NewOrder(account AcmeAccount, identifiers []AcmeIdentifier) (AcmeOrder, error) {
	newOrderReq := struct {
		Identifiers []AcmeIdentifier `json:"identifiers"`
	}{
		Identifiers: identifiers,
	}
	newOrderResp := AcmeOrder{}
	resp, err := c.post(c.dir.NewOrder, account.Url, account.PrivateKey, newOrderReq, &newOrderResp, http.StatusCreated)
	if err != nil {
		return newOrderResp, err
	}

	url, err := resp.Location()
	if err != nil {
		return newOrderResp, fmt.Errorf("acme: error getting new order location: %v", err)
	}
	newOrderResp.Url = url.String()

	return newOrderResp, nil
}

func (c AcmeClient) FetchOrder(orderUrl string) (AcmeOrder, error) {
	orderResp := AcmeOrder{
		Url: orderUrl, // boulder response doesn't seem to contain location header for this request
	}
	_, err := c.get(orderUrl, &orderResp, http.StatusOK)
	if err != nil {
		return orderResp, err
	}

	return orderResp, nil
}

func (c AcmeClient) FetchAuthorization(account AcmeAccount, authUrl string) (AcmeAuthorization, error) {
	authResp := AcmeAuthorization{}
	_, err := c.get(authUrl, &authResp, http.StatusOK)
	if err != nil {
		return authResp, err
	}

	for i := 0; i < len(authResp.Challenges); i++ {
		if authResp.Challenges[i].KeyAuthorization == "" {
			authResp.Challenges[i].KeyAuthorization = authResp.Challenges[i].Token + "." + account.Thumbprint
		}
	}

	authResp.ChallengeMap = map[string]AcmeChallenge{}
	authResp.ChallengeTypes = []string{}
	for _, c := range authResp.Challenges {
		authResp.ChallengeMap[c.Type] = c
		authResp.ChallengeTypes = append(authResp.ChallengeTypes, c.Type)
	}

	return authResp, nil
}

func EncodeDns01KeyAuthorization(keyAuth string) string {
	h := sha256.New()
	h.Write([]byte(keyAuth))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func (c AcmeClient) UpdateChallenge(account AcmeAccount, challenge AcmeChallenge) (AcmeChallenge, error) {
	chalReq := struct {
		KeyAuthorization string `json:"keyAuthorization"`
	}{
		KeyAuthorization: challenge.KeyAuthorization,
	}

	if _, err := c.post(challenge.Url, account.Url, account.PrivateKey, chalReq, &challenge, http.StatusOK); err != nil {
		return challenge, err
	}
	if challenge.Error.Type != "" {
		return challenge, challenge.Error
	}

	switch challenge.Status {
	case "valid":
		return challenge, nil
	case "invalid":
		// this should be cause by the error.type check above, so if it gets here there must have been no error
		return challenge, errors.New("acme: challenge is invalid, no error provided")
	case "pending":
		// do nothing
	default:
		return challenge, fmt.Errorf("acme: unknown challenge status: %s", challenge.Status)
	}

	// TODO: check to see if they've provided a Retry-After header, maybe use it?
	// boulder doesnt seem to provide a retry-after

	pollInterval := c.PollInterval
	if pollInterval == 0 {
		pollInterval = time.Second
	}
	pollTimeout := c.PollTimeout
	if pollTimeout == 0 {
		pollTimeout = 30 * time.Second
	}
	end := time.Now().Add(pollTimeout)
	for {
		if time.Now().After(end) {
			return challenge, errors.New("acme: challenge update timeout")
		}
		time.Sleep(pollInterval)

		if _, err := c.get(challenge.Url, &challenge, http.StatusOK); err != nil {
			// i dont think it's worth exiting the loop on this error
			// it could just be connectivity issue thats resolved before the timeout duration
			continue
		}
		if challenge.Error.Type != "" {
			return challenge, challenge.Error
		}

		switch challenge.Status {
		case "valid":
			return challenge, nil
		case "invalid":
			// this should be cause by the error.type check above, so if it gets here there must have been no error
			return challenge, errors.New("acme: challenge is invalid, no error provided")
		case "pending":
			// do nothing
		default:
			return challenge, fmt.Errorf("acme: unknown challenge status: %s", challenge.Status)
		}
	}
}

func (c AcmeClient) FinalizeOrder(account AcmeAccount, order AcmeOrder, csr *x509.CertificateRequest) (AcmeOrder, error) {
	finaliseReq := struct {
		Csr string `json:"csr"`
	}{
		Csr: base64.RawURLEncoding.EncodeToString(csr.Raw),
	}

	finalizeResp := AcmeOrder{}
	resp, err := c.post(order.Finalize, account.Url, account.PrivateKey, finaliseReq, &finalizeResp, http.StatusOK)
	if err != nil {
		return finalizeResp, err
	}
	if finalizeResp.Error.Type != "" {
		return finalizeResp, finalizeResp.Error
	}

	url, err := resp.Location()
	if err != nil {
		return finalizeResp, fmt.Errorf("acme: error getting finalized order location: %v", err)
	}
	finalizeResp.Url = url.String()

	switch finalizeResp.Status {
	case "invalid":
		// this should be cause by the error.type check above, so if it gets here there must have been no error
		return finalizeResp, errors.New("acme: finalized order is invalid, no error provided")
	case "pending":
		return finalizeResp, errors.New("acme: authorizations not fulfilled")
	case "processing":
		// do nothing
	case "valid":
		return finalizeResp, nil
	default:
		return finalizeResp, fmt.Errorf("acme: unknown finalized order status: %s", finalizeResp.Status)
	}

	// TODO: check to see if they've provided a Retry-After header, maybe use it?
	// boulder doesnt seem to provide a retry-after

	pollInterval := c.PollInterval
	if pollInterval == 0 {
		pollInterval = time.Second
	}
	pollTimeout := c.PollTimeout
	if pollTimeout == 0 {
		pollTimeout = 30 * time.Second
	}
	end := time.Now().Add(pollTimeout)
	for {
		if time.Now().After(end) {
			return finalizeResp, errors.New("acme: finalized order timeout")
		}
		time.Sleep(pollInterval)

		if _, err := c.get(finalizeResp.Url, &finalizeResp, http.StatusOK); err != nil {
			// i dont think it's worth exiting the loop on this error
			// it could just be connectivity issue thats resolved before the timeout duration
			continue
		}
		if finalizeResp.Error.Type != "" {
			return finalizeResp, finalizeResp.Error
		}

		switch finalizeResp.Status {
		case "invalid":
			// this should be cause by the error.type check above, so if it gets here there must have been no error
			return finalizeResp, errors.New("acme: finalized order is invalid, no error provided")
		case "pending":
			return finalizeResp, errors.New("acme: authorizations not fulfilled")
		case "processing":
			// do nothing
		case "valid":
			return finalizeResp, nil
		default:
			return finalizeResp, fmt.Errorf("acme: unknown finalized order status: %s", finalizeResp.Status)
		}
	}
}
