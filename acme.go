package acme

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"log"

	"io"

	"regexp"

	"strings"

	"crypto/ecdsa"
	"crypto/rsa"

	"gopkg.in/square/go-jose.v2"
)

// Creates a new directory client given a valid directory url.
// https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-7.1.1
func NewClient(directoryUrl string) (AcmeClient, error) {
	ns := &nonceStack{}

	client := AcmeClient{
		client: &http.Client{
			Transport: ns,
			Timeout:   time.Second * 30,
		},
		nonces: ns,
	}

	if _, err := client.get(directoryUrl, &client.dir, http.StatusOK); err != nil {
		return client, err
	}

	client.dir.Directory = directoryUrl
	ns.newNonceUrl = client.dir.NewNonce

	return client, nil
}

// Helper function to have a central point for performing http requests.
// Mostly just used for debugging.
func (c AcmeClient) do(req *http.Request) (*http.Response, error) {
	// https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-6.1
	// identifier for this client, as well as the default go user agent
	req.Header.Set("User-Agent", "eggsampler-acme/1.0 Go-http-client/1.1")

	resp, err := c.client.Do(req)
	if Debug {
		log.Printf("DEBUG %s URL: %s", req.Method, req.URL)
	}
	if err != nil {
		return resp, err
	}
	if Debug {
		log.Printf("DEBUG HEADERS: %+v", resp.Header)
	}
	return resp, nil
}

// Helper function to have a central point for reading http response bodies.
// Mostly just used for debugging.
func readBody(r io.Reader) ([]byte, error) {
	body, err := ioutil.ReadAll(r)
	if err != nil {
		return body, err
	}
	if Debug {
		log.Printf("DEBUG BODY: %s", string(body))
	}
	return body, nil
}

// Helper function to perform an http get request and read the body.
func (c AcmeClient) getRaw(url string, expectedStatus ...int) (*http.Response, []byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("acme: error creating request: %v", err)
	}

	resp, err := c.do(req)
	if err != nil {
		return resp, nil, fmt.Errorf("acme: error fetching response: %v", err)
	}
	defer resp.Body.Close()

	if err := checkError(resp, expectedStatus...); err != nil {
		return resp, nil, err
	}

	body, err := readBody(resp.Body)
	if err != nil {
		return resp, body, fmt.Errorf("acme: error reading response body: %v", err)
	}

	return resp, body, nil
}

// Helper function for performing a http get on an acme resource.
func (c AcmeClient) get(url string, out interface{}, expectedStatus ...int) (*http.Response, error) {
	resp, body, err := c.getRaw(url, expectedStatus...)
	if err != nil {
		return resp, err
	}

	if len(body) > 0 && out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return resp, fmt.Errorf("acme: error parsing response body: %v", err)
		}
	}

	return resp, nil
}

// Encapsulates a payload into a JSON Web Signature
// https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-6.2
func encapsulateJws(nonceSource jose.NonceSource, requestUrl, keyId string, privateKey interface{}, payload interface{}) (*jose.JSONWebSignature, error) {
	keyAlgo, err := keyAlgorithm(privateKey)
	if err != nil {
		return nil, err
	}

	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("acme: error marshalling payload: %v", err)
	}

	opts := jose.SignerOptions{}
	if nonceSource != nil {
		opts.NonceSource = nonceSource
	}
	opts.WithHeader("url", requestUrl)
	// jwk and kid fields are mutually exclusive
	if keyId != "" {
		opts.WithHeader("kid", keyId)
	} else {
		opts.EmbedJWK = true
	}

	sig := jose.SigningKey{
		Key:       privateKey,
		Algorithm: keyAlgo,
	}

	signer, err := jose.NewSigner(sig, &opts)
	if err != nil {
		return nil, fmt.Errorf("acme: error creating new signer: %v", err)
	}

	object, err := signer.Sign(rawPayload)
	if err != nil {
		return object, fmt.Errorf("acme: error signing payload: %v", err)
	}

	return object, nil
}

// Helper function to perform an http post request and read the body.
func (c AcmeClient) postRaw(requestUrl string, payload io.Reader, expectedStatus ...int) (*http.Response, []byte, error) {
	req, err := http.NewRequest("POST", requestUrl, payload)
	if err != nil {
		return nil, nil, fmt.Errorf("acme: error creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/jose+json")

	resp, err := c.do(req)
	if err != nil {
		return resp, nil, fmt.Errorf("acme: error sending request: %v", err)
	}
	defer resp.Body.Close()

	if err := checkError(resp, expectedStatus...); err != nil {
		return resp, nil, err
	}

	body, err := readBody(resp.Body)
	if err != nil {
		return resp, body, fmt.Errorf("acme: error reading response body: %v", err)
	}

	return resp, body, nil
}

// Helper function for performing a http post to an acme resource.
func (c AcmeClient) post(requestUrl, keyId string, privateKey interface{}, payload interface{}, out interface{}, expectedStatus ...int) (*http.Response, error) {
	object, err := encapsulateJws(c.nonces, requestUrl, keyId, privateKey, payload)
	if err != nil {
		return nil, err
	}

	resp, body, err := c.postRaw(requestUrl, strings.NewReader(object.FullSerialize()), expectedStatus...)
	if err != nil {
		return resp, err
	}

	if len(body) > 0 && out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return resp, fmt.Errorf("acme: error parsing response: %v - %s", err, string(body))
		}
	}

	return resp, nil
}

var regLink = regexp.MustCompile(`<(.+?)>;\s*rel="(.+?)"`)

// Parses a Link header from a http response into an map for lookup
func parseLinks(link []string) map[string]string {
	if len(link) == 0 {
		return nil
	}
	links := map[string]string{}
	for _, l := range link {
		matches := regLink.FindAllStringSubmatch(l, -1)
		for _, m := range matches {
			if len(m) == 3 {
				links[m[2]] = m[1]
			}
		}
	}
	return links
}

func keyAlgorithm(privateKey interface{}) (jose.SignatureAlgorithm, error) {
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		return jose.RS256, nil
	case *ecdsa.PrivateKey:
		switch k.Params().Name {
		case "P-256":
			return jose.ES256, nil
		case "P-384":
			return jose.ES384, nil
		case "P-521":
			return jose.ES512, nil
		default:
			return "", fmt.Errorf("acme: unsupported private key ecdsa params: %s", k.Params().Name)
		}
	default:
		return "", fmt.Errorf("acme: unsupported private key type: %v", k)
	}
}
