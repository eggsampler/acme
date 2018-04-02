package acme

import (
	"crypto/tls"
	"net/http"
	"time"
)

// Function prototype for passing options to NewClient
type AcmeOptionFunc func(client AcmeClient) error

// Option function which sets a timeout on the http client used by the AcmeClient
func WithHttpTimeout(duration time.Duration) AcmeOptionFunc {
	return func(client AcmeClient) error {
		client.httpClient.Timeout = duration
		return nil
	}
}

// Option function which sets InsecureSkipVerify on the http client transport tls client config used by the AcmeClient
func WithInsecureSkipVerify() AcmeOptionFunc {
	return func(client AcmeClient) error {
		client.httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		return nil
	}
}
