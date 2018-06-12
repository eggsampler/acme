package acme

import (
	"crypto/tls"
	"net/http"
	"time"
)

// OptionFunc function prototype for passing options to NewClient
type OptionFunc func(client Client) error

// WithHTTPTimeout sets a timeout on the http client used by the Client
func WithHTTPTimeout(duration time.Duration) OptionFunc {
	return func(client Client) error {
		client.httpClient.Timeout = duration
		return nil
	}
}

// WithInsecureSkipVerify sets InsecureSkipVerify on the http client transport tls client config used by the Client
func WithInsecureSkipVerify() OptionFunc {
	return func(client Client) error {
		client.httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		return nil
	}
}
