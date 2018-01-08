package acme

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
)

// Downloads a certificate from the given url.
// https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-7.4.2
func (c AcmeClient) FetchCertificate(certificateUrl string) ([]*x509.Certificate, error) {
	resp, b, err := c.getRaw(certificateUrl, http.StatusOK)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	for {
		p, b := pem.Decode(b)
		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return certs, fmt.Errorf("acme: parsing certificate: %v", err)
		}
		certs = append(certs, cert)
		if len(b) == 0 {
			break
		}
	}

	links := parseLinks(resp.Header["Link"])
	up := links["up"]
	if up != "" {
		upCerts, err := c.FetchCertificate(up)
		if err != nil {
			return certs, fmt.Errorf("acme: error fetching up cert: %v", err)
		}
		if len(upCerts) != 0 {
			certs = append(certs, upCerts...)
		}
	}

	return certs, nil
}

// NOTE: this is a let's encrypt specific thing which should only be used when the issuer certificate
// isn't returned when using FetchCertificate
func (c AcmeClient) FetchIssuerCertificate() (*x509.Certificate, error) {
	u, err := url.Parse(c.dir.Directory)
	if err != nil {
		return nil, fmt.Errorf("acme: error parsing directory url: %v", err)
	}

	u.Path = "/acme/issuer-cert"
	u.RawPath = u.Path
	_, raw, err := c.getRaw(u.String(), http.StatusOK)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return cert, fmt.Errorf("acme: error parsing issuer certificate: %v", err)
	}

	return cert, nil
}

// Revokes a given certificate.
// https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-7.6
func (c AcmeClient) RevokeCertificate(account AcmeAccount, cert *x509.Certificate, reason int) error {
	revokeReq := struct {
		Certificate string `json:"certificate"`
		Reason      int    `json:"reason"`
	}{
		Certificate: base64.RawURLEncoding.EncodeToString(cert.Raw),
		Reason:      reason,
	}

	_, err := c.post(c.dir.RevokeCert, "", account.SigningKey, revokeReq, nil, http.StatusOK)

	return err
}
