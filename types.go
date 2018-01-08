package acme

import (
	"net/http"
	"time"

	"gopkg.in/square/go-jose.v2"
)

var Debug = false

var (
	AcmeChallengeDns01    = "dns-01"
	AcmeChallengeHttp01   = "http-01"
	AcmeChallengeTlsSni02 = "tls-sni-02"
)

// Constants used for certificate revocation, used for RevokeCertificate
// https://tools.ietf.org/html/rfc5280#section-5.3.1
const (
	ReasonUnspecified          = iota // 0
	ReasonKeyCompromise               // 1
	ReasonCaCompromise                // 2
	ReasonAffiliationChanged          // 3
	ReasonSuperseded                  // 4
	ReasonCessationOfOperation        // 5
	ReasonCertificateHold             // 6
	_
	ReasonRemoveFromCRL      // 8
	ReasonPrivilegeWithdrawn // 9
	ReasonAaCompromise       // 10
)

type AcmeDirectory struct {
	Directory  string `json:"-"`
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	NewAuthz   string `json:"newAuthz"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
	Meta       struct {
		TermsOfService          string   `json:"termsOfService"`
		Website                 string   `json:"website"`
		CaaIdentities           []string `json:"caaIdentities"`
		ExternalAccountRequired bool     `json:"externalAccountRequired"`
	} `json:"meta"`
}

type AcmeClient struct {
	client *http.Client
	nonces *nonceStack
	dir    AcmeDirectory

	PollTimeout  time.Duration
	PollInterval time.Duration
}

type AcmeAccount struct {
	Url        string          `json:"-"`
	SigningKey jose.SigningKey `json:"-"`
	Thumbprint string          `json:"-"`

	Status               string   `json:"status"`
	Contact              []string `json:"contact"`
	TermsOfServiceAgreed bool     `json:"onlyReturnExisting"`
	Orders               string   `json:"orders"`
}

type AcmeIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type AcmeOrder struct {
	Url string `json:"-"`

	Status         string           `json:"status"`
	Expires        time.Time        `json:"expires"`
	Identifiers    []AcmeIdentifier `json:"identifiers"`
	Authorizations []string         `json:"authorizations"`
	Error          AcmeError        `json:"error"`
	Finalize       string           `json:"finalize"`
	Certificate    string           `json:"certificate"`
}

type AcmeAuthorization struct {
	Identifier AcmeIdentifier  `json:"identifier"`
	Status     string          `json:"status"`
	Expires    time.Time       `json:"expires"`
	Challenges []AcmeChallenge `json:"challenges"`

	ChallengeMap   map[string]AcmeChallenge `json:"-"`
	ChallengeTypes []string                 `json:"-"`
}

type AcmeChallenge struct {
	Type             string    `json:"type"`
	Status           string    `json:"status"`
	Url              string    `json:"url"`
	Token            string    `json:"token"`
	Error            AcmeError `json:"error"`
	KeyAuthorization string    `json:"keyAuthorization"`
}
