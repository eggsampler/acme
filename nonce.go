package acme

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type nonceStack struct {
	newNonceUrl string
	lock        sync.Mutex
	stack       []string
}

func (ns *nonceStack) push(v string) {
	ns.lock.Lock()
	defer ns.lock.Unlock()

	if len(ns.stack) > 100 {
		return
	}

	ns.stack = append(ns.stack, v)
}

// NonceSource in gopkg.in/square/go-jose.v2/signing.go
// Used to insert a nonce field into a jws header.
func (ns *nonceStack) Nonce() (string, error) {
	ns.lock.Lock()
	defer ns.lock.Unlock()

	n := len(ns.stack)
	if n == 0 {
		if ns.newNonceUrl == "" {
			return "", errors.New("acme: no directory url")
		}
		c := http.Client{Timeout: 10 * time.Second}
		resp, err := c.Head(ns.newNonceUrl)
		if err != nil {
			return "", fmt.Errorf("acme: error fetching new nonce: %v", err)
		}
		nonce := resp.Header.Get("Replay-Nonce")
		if nonce == "" {
			return "", errors.New("acme: no nonce sent")
		}
		return nonce, nil
	}

	v := ns.stack[n-1]
	ns.stack = ns.stack[:n-1]

	return v, nil
}

// RoundTripper in net/http/client.go
// Used to extract valid nonces from http requests to an acme resource.
func (ns *nonceStack) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	var rt http.RoundTripper
	if Debug {
		rt = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	} else {
		rt = http.DefaultTransport
	}

	resp, err = rt.RoundTrip(req)
	if err != nil {
		return
	}

	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return
	}

	ns.push(nonce)

	return
}
