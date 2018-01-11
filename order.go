package acme

import (
	"net/http"

	"encoding/base64"

	"fmt"

	"time"

	"errors"

	"crypto/x509"
)

// Initiates a new order for a new certificate.
// https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-7.4
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

	newOrderResp.Url = resp.Header.Get("Location")

	return newOrderResp, nil
}

// Fetches an existing order given an order url.
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

// Helper function to determine whether an order is "finished" by it's status.
func checkOrderStatus(order AcmeOrder) (bool, error) {
	switch order.Status {
	case "invalid":
		if order.Error.Type != "" {
			return true, order.Error
		}
		return true, errors.New("acme: finalized order is invalid, no error provided")
	case "pending":
		return true, errors.New("acme: authorizations not fulfilled")
	case "processing":
		return false, nil
	case "valid":
		return true, nil
	default:
		return true, fmt.Errorf("acme: unknown order status: %s", order.Status)
	}
}

// Indicates to the acme server that the client considers an order complete and "finalizes" it.
// If the server believes the authorizations have been filled successfully, a certificate should then be available.
// https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-7.4
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

	finalizeResp.Url = resp.Header.Get("Location")

	if finished, err := checkOrderStatus(finalizeResp); finished {
		return finalizeResp, err
	}

	pollInterval, pollTimeout := c.getPollingDurations()
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

		finalizeResp.Url = resp.Header.Get("Location")

		if finished, err := checkOrderStatus(finalizeResp); finished {
			return finalizeResp, err
		}
	}
}

// Fetches a list of orders given an account orders url.
// Takes a url so the "next" http Link header can be used.
// https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-7.1.2.1
func (c AcmeClient) FetchOrdersList(ordersUrl string) (AcmeOrderList, error) {
	orderListResp := AcmeOrderList{}
	resp, err := c.get(ordersUrl, &orderListResp, http.StatusOK)
	if err != nil {
		return orderListResp, err
	}

	orderListResp.Next = fetchLink(resp, "next")

	return orderListResp, nil
}
