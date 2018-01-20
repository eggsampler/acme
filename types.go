package acme

import (
	"net/http"
	"time"
)

// Turns on debug mode. Currently, debug mode is only for disabling TLS checks for the http client.
var Debug = false

// Different possible challenge types provided by an ACME server.
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

// A directory object as returned from the client's directory url upon creation of client.
// https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-7.1.1
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

// A client structure to interact with an ACME server.
// This is typically be how most, if not all, of the communication between the client and server occurs.
type AcmeClient struct {
	httpClient *http.Client
	nonces     *nonceStack
	dir        AcmeDirectory

	// The amount of total time the AcmeClient will wait at most for a challenge to be updated or a certificate to be issued.
	// Default 30 seconds if duration is not set or 0.
	PollTimeout time.Duration

	// The time between checking if a challenge has been updated or a certificate has been issued.
	// Default 0.5 seconds if duration is not set or 0.
	PollInterval time.Duration
}

// A structure representing fields in an account object.
// https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-7.1.2
type AcmeAccount struct {
	Status               string   `json:"status"`
	Contact              []string `json:"contact"`
	TermsOfServiceAgreed bool     `json:"onlyReturnExisting"`
	Orders               string   `json:"orders"`

	// Provided by the Location http header when creating a new account or fetching an existing account.
	Url string `json:"-"`

	// The private key used to create or fetch the account.
	// Not fetched from server.
	PrivateKey interface{} `json:"-"`

	// SHA-256 digest JWK_Thumbprint of the account key.
	// Used in updating challenges, see: https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-8.1
	Thumbprint string `json:"-"`
}

// An identifier object used in order and authorization objects
// https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-7.1.3
type AcmeIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// An order object, returned when fetching or creating a new order.
// https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-7.1.3
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

// An authorization object returned when fetching an authorization in an order.
// https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-7.1.4
type AcmeAuthorization struct {
	Identifier AcmeIdentifier  `json:"identifier"`
	Status     string          `json:"status"`
	Expires    time.Time       `json:"expires"`
	Challenges []AcmeChallenge `json:"challenges"`

	// For convenience access to the provided challenges
	ChallengeMap   map[string]AcmeChallenge `json:"-"`
	ChallengeTypes []string                 `json:"-"`
}

// A challenge object fetched in an authorization or directly from the challenge url.
// https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-8
type AcmeChallenge struct {
	Type             string    `json:"type"`
	Status           string    `json:"status"`
	Url              string    `json:"url"`
	Token            string    `json:"token"`
	Error            AcmeError `json:"error"`
	KeyAuthorization string    `json:"keyAuthorization"`

	// Authorization url provided by the rel="up" Link http header
	AuthorizationUrl string `json:"-"`
}

// An orders list challenge object.
// https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-7.1.2.1
type AcmeOrderList struct {
	Orders []string `json:"orders"`

	// Order list pagination, url to next orders.
	// Provided by the rel="next" Link http header
	Next string `json:"-"`
}
