package acme

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type (
	RenewalInfo struct {
		SuggestedWindow struct {
			Start time.Time `json:"start"`
			End   time.Time `json:"end"`
		} `json:"suggestedWindow"`
		ExplanationURL string `json:"explanationURL"`
	}
)

var (
	ErrRenewalInfoNotSupported = errors.New("renewal information endpoint not")
)

// GetRenewalInfo returns the renewal information (if present and supported by the ACME server), and
// a Retry-After time if indicated in the http response header.
func (c Client) GetRenewalInfo(cert, issuer *x509.Certificate, hash crypto.Hash) (RenewalInfo, time.Time, error) {

	if len(c.dir.RenewalInfo) == 0 {
		return RenewalInfo{}, time.Time{}, ErrRenewalInfoNotSupported
	}

	certID, err := generateCertID(cert, issuer, hash)
	if err != nil {
		return RenewalInfo{}, time.Time{}, fmt.Errorf("error generating certificate id: %w", err)
	}

	renewalURL := c.dir.RenewalInfo
	if !strings.HasSuffix(renewalURL, "/") {
		renewalURL += "/"
	}
	renewalURL += certID
	var ri RenewalInfo

	resp, err := c.get(renewalURL, &ri, http.StatusOK)
	if err != nil {
		return ri, time.Time{}, err
	}

	retryAfterString := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if len(retryAfterString) == 0 {
		return ri, time.Time{}, nil
	}

	if retryAfterTime, err := time.Parse(time.RFC1123, retryAfterString); err == nil {
		return ri, retryAfterTime, nil
	}

	if retryAfterInt, err := strconv.Atoi(retryAfterString); err == nil {
		return ri, time.Now().Add(time.Second * time.Duration(retryAfterInt)), nil
	}

	return ri, time.Time{}, fmt.Errorf("error parsing Retry-After: unsupported time: %s", retryAfterString)
}

// UpdateRenewalInfo sends a request to the acme server to indicate the renewal info is updated.
// replaced should always be true.
func (c Client) UpdateRenewalInfo(account Account, cert, issuer *x509.Certificate, hash crypto.Hash, replaced bool) error {

	if len(c.dir.RenewalInfo) == 0 {
		return ErrRenewalInfoNotSupported
	}

	certID, err := generateCertID(cert, issuer, hash)
	if err != nil {
		return fmt.Errorf("error generating certificate id: %w", err)
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

func generateCertID(cert, issuer *x509.Certificate, hashFunc crypto.Hash) (string, error) {
	oid, ok := hashOIDs[hashFunc]
	if !ok {
		var s []string
		for k, _ := range hashOIDs {
			s = append(s, k.String())
		}
		return "", fmt.Errorf("unsupported hash algorithm %q, currently available: %q", hashFunc.String(), strings.Join(s, ","))
	}

	if !hashFunc.Available() {
		return "", x509.ErrUnsupportedAlgorithm
	}

	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return "", err
	}

	h := hashFunc.New()
	h.Write(issuer.RawSubject)
	issuerNameHash := h.Sum(nil)

	h.Reset()
	h.Write(publicKeyInfo.PublicKey.RightAlign())
	issuerKeyHash := h.Sum(nil)

	s := struct {
		HashAlgorithm struct {
			AlgorithmIdentifier asn1.ObjectIdentifier
		}
		IssuerNameHash []uint8
		IssuerKeyHash  []uint8
		SerialNumber   *big.Int
	}{
		HashAlgorithm: struct {
			AlgorithmIdentifier asn1.ObjectIdentifier
		}{
			AlgorithmIdentifier: oid,
		},
		IssuerNameHash: issuerNameHash,
		IssuerKeyHash:  issuerKeyHash,
		SerialNumber:   cert.SerialNumber,
	}
	b, err := asn1.Marshal(s)
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "="), err
}

// from https://cs.opensource.google/go/x/crypto/+/refs/tags/v0.8.0:ocsp/ocsp.go;l=156
var hashOIDs = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.SHA1:   asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26}),
	crypto.SHA256: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1}),
	crypto.SHA384: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 2}),
	crypto.SHA512: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 3}),
}
