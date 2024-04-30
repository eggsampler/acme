package acme

import (
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type (
	// RenewalInfo is returned by Client.GetRenewalInfo
	RenewalInfo struct {
		SuggestedWindow struct {
			Start time.Time `json:"start"`
			End   time.Time `json:"end"`
		} `json:"suggestedWindow"`
		ExplanationURL string `json:"explanationURL"`

		RetryAfter time.Time `json:"-"`
	}
)

var (
	// ErrRenewalInfoNotSupported is returned by Client.GetRenewalInfo and Client.UpdateRenewalInfo if the renewal info
	// entry isn't present on the acme directory (ie, it's not supported by the acme server)
	ErrRenewalInfoNotSupported = errors.New("renewal information endpoint not")
)

// GetRenewalInfo returns the renewal information (if present and supported by the ACME server), and
// a Retry-After time if indicated in the http response header.
func (c Client) GetRenewalInfo(cert *x509.Certificate) (RenewalInfo, error) {

	if c.dir.RenewalInfo == "" {
		return RenewalInfo{}, ErrRenewalInfoNotSupported
	}

	certID, err := generateARICertID(cert)
	if err != nil {
		return RenewalInfo{}, fmt.Errorf("error generating certificate id: %v", err)
	}

	renewalURL := c.dir.RenewalInfo
	if !strings.HasSuffix(renewalURL, "/") {
		renewalURL += "/"
	}
	renewalURL += certID
	var ri RenewalInfo

	resp, err := c.get(renewalURL, &ri, http.StatusOK)
	if err != nil {
		return ri, err
	}

	ri.RetryAfter, err = parseRetryAfter(resp.Header.Get("Retry-After"))
	return ri, err
}

// UpdateRenewalInfo sends a request to the acme server to indicate the renewal info is updated.
// replaced should always be true.
func (c Client) UpdateRenewalInfo(account Account, cert *x509.Certificate, replaced bool) error {

	if len(c.dir.RenewalInfo) == 0 {
		return ErrRenewalInfoNotSupported
	}

	certID, err := generateARICertID(cert)
	if err != nil {
		return fmt.Errorf("error generating certificate id: %v", err)
	}

	updateReq := struct {
		CertID   string `json:"certID"`
		Replaced bool   `json:"replaced"`
	}{
		CertID:   certID,
		Replaced: replaced,
	}

	_, err = c.post(c.dir.RenewalInfo, account.URL, account.PrivateKey, updateReq, nil, http.StatusOK)

	return err
}

// generateARICertID
func generateARICertID(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", fmt.Errorf("certificate not found")
	}

	derBytes, err := asn1.Marshal(cert.SerialNumber)
	if err != nil {
		return "", nil
	}

	if len(derBytes) < 3 {
		return "", fmt.Errorf("invalid DER encoding of serial number")
	}

	// Extract only the integer bytes from the DER encoded Serial Number
	// Skipping the first 2 bytes (tag and length). The result is base64url
	// encoded without padding.
	serial := base64.RawURLEncoding.EncodeToString(derBytes[2:])

	// Convert the Authority Key Identifier to base64url encoding without
	// padding.
	aki := base64.RawURLEncoding.EncodeToString(cert.AuthorityKeyId)

	// Construct the final identifier by concatenating AKI and Serial Number.
	return fmt.Sprintf("%s.%s", aki, serial), nil
}

// timeNow and implementations support testing
type timeNow interface {
	Now() time.Time
}

type currentTimeNow struct{}

func (currentTimeNow) Now() time.Time {
	return time.Now()
}

var systemTime timeNow = currentTimeNow{}

func parseRetryAfter(ra string) (time.Time, error) {
	retryAfterString := strings.TrimSpace(ra)
	if len(retryAfterString) == 0 {
		return time.Time{}, nil
	}

	if retryAfterTime, err := time.Parse(time.RFC1123, retryAfterString); err == nil {
		return retryAfterTime, nil
	}

	if retryAfterInt, err := strconv.Atoi(retryAfterString); err == nil {
		return systemTime.Now().Add(time.Second * time.Duration(retryAfterInt)), nil
	}

	return time.Time{}, fmt.Errorf("invalid time format: %s", retryAfterString)
}
