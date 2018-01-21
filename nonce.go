package acme

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
)

// Simple thread-safe stack impl
type nonceStack struct {
	lock  sync.Mutex
	stack []string

	client      http.Client
	newNonceURL string
}

// Pushes a nonce to the stack.
// Doesn't push empty nonces, or if there's more than 100 nonces on the stack
func (ns *nonceStack) push(v string) {
	if v == "" {
		return
	}

	ns.lock.Lock()
	defer ns.lock.Unlock()

	if len(ns.stack) > 100 {
		return
	}

	ns.stack = append(ns.stack, v)
}

// Pops a nonce from the stack.
// Returns empty string if there are no nonces
func (ns *nonceStack) pop() string {
	ns.lock.Lock()
	defer ns.lock.Unlock()

	n := len(ns.stack)
	if n == 0 {
		return ""
	}

	v := ns.stack[n-1]
	ns.stack = ns.stack[:n-1]

	return v
}

// NonceSource in gopkg.in/square/go-jose.v2/signing.go
// Used to insert a nonce field into a jws header.
func (ns *nonceStack) Nonce() (string, error) {
	nonce := ns.pop()
	if nonce != "" {
		return nonce, nil
	}

	if ns.newNonceURL == "" {
		return "", errors.New("acme: no newNonce url")
	}

	req, err := http.NewRequest("HEAD", ns.newNonceURL, nil)
	if err != nil {
		return "", fmt.Errorf("acme: error creating newNonce request: %v", err)
	}
	req.Header.Set("User-Agent", userAgentString)

	resp, err := ns.client.Head(ns.newNonceURL)
	if err != nil {
		return "", fmt.Errorf("acme: error fetching new nonce: %v", err)
	}

	replaceNonce := resp.Header.Get("Replay-Nonce")
	if replaceNonce == "" {
		return "", errors.New("acme: no nonce sent")
	}

	return replaceNonce, nil
}
