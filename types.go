package acme

import (
	"net/http"
	"time"
)

// Turns on debug mode. Currently, debug mode is only for disabling TLS checks for the http client.
var Debug = false

var (
	AcmeChallengeTypeDns01    = "dns-01"
	AcmeChallengeTypeHttp01   = "http-01"
	AcmeChallengeTypeTlsSni02 = "tls-sni-02"
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
	_                                 // 7 - Unused
	ReasonRemoveFromCRL               // 8
	ReasonPrivilegeWithdrawn          // 9
	ReasonAaCompromise                // 10
)

type AcmeDirectory struct {
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

	Directory string `json:"-"`
}

type AcmeClient struct {
	httpClient *http.Client
	nonces     *nonceStack
	dir        AcmeDirectory

	PollTimeout  time.Duration // Default 30 seconds
	PollInterval time.Duration // Default 0.5 seconds
}

type AcmeAccount struct {
	Status               string   `json:"status"`
	Contact              []string `json:"contact"`
	TermsOfServiceAgreed bool     `json:"onlyReturnExisting"`
	Orders               string   `json:"orders"`

	Url        string      `json:"-"` // Provided by the Location http header
	PrivateKey interface{} `json:"-"`
	Thumbprint string      `json:"-"` // SHA-256 digest JWK_Thumbprint of the account key
}

type AcmeIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type AcmeOrder struct {
	Status         string           `json:"status"`
	Expires        time.Time        `json:"expires"`
	Identifiers    []AcmeIdentifier `json:"identifiers"`
	Authorizations []string         `json:"authorizations"`
	Error          AcmeError        `json:"error"`
	Finalize       string           `json:"finalize"`
	Certificate    string           `json:"certificate"`

	Url string `json:"-"` // Provided by the rel="Location" Link http header
}

type AcmeAuthorization struct {
	Identifier AcmeIdentifier  `json:"identifier"`
	Status     string          `json:"status"`
	Expires    time.Time       `json:"expires"`
	Challenges []AcmeChallenge `json:"challenges"`

	// For convenience access to the provided challenges
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

	AuthorizationUrl string `json:"-"` // Provided by the rel="up" Link http header
}

type AcmeOrderList struct {
	Orders []string `json:"orders"`

	Next string `json:"-"` // Provided by the rel="next" Link http header
}
