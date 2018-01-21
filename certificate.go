package acme

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
)

// Downloads a certificate from the given url.
// More details: https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-7.4.2
func (c AcmeClient) FetchCertificates(certificateUrl string) ([]*x509.Certificate, error) {
	resp, raw, err := c.getRaw(certificateUrl, http.StatusOK)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	for {
		var p *pem.Block
		p, raw = pem.Decode(raw)
		if p == nil {
			break
		}
		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return certs, fmt.Errorf("acme: parsing certificate: %v", err)
		}
		certs = append(certs, cert)
	}

	up := fetchLink(resp, "up")
	if up != "" {
		upCerts, err := c.FetchCertificates(up)
		if err != nil {
			return certs, fmt.Errorf("acme: error fetching up cert: %v", err)
		}
		if len(upCerts) != 0 {
			certs = append(certs, upCerts...)
		}
	}

	return certs, nil
}

// Revokes a given certificate.
// More details: https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-7.6
func (c AcmeClient) RevokeCertificate(account AcmeAccount, cert *x509.Certificate, certPrivKey interface{}, reason int) error {
	revokeReq := struct {
		Certificate string `json:"certificate"`
		Reason      int    `json:"reason"`
	}{
		Certificate: base64.RawURLEncoding.EncodeToString(cert.Raw),
		Reason:      reason,
	}

	if _, err := c.post(c.Directory.RevokeCert, "", certPrivKey, revokeReq, nil, http.StatusOK); err != nil {
		return err
	}

	return nil
}
