package acme

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestClient_GetRenewalInfo(t *testing.T) {
	account, order, _ := makeOrderFinalised(t, nil)
	if order.Certificate == "" {
		t.Fatalf("no certificate: %+v", order)
	}
	certs, err := testClient.FetchCertificates(account, order.Certificate)
	t.Logf("Issued serial %s\n", certs[0].SerialNumber.String())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(certs) < 2 {
		t.Fatalf("no certs")
	}

	renewalInfo, err := testClient.GetRenewalInfo(certs[0])
	t.Logf("Suggested renewal window for new issuance: %v\n", renewalInfo.SuggestedWindow)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if renewalInfo.RetryAfter.IsZero() {
		t.Fatalf("no retry after provided")
	}
	if renewalInfo.SuggestedWindow.Start.Before(time.Now()) {
		t.Fatalf("suggested window start is in the past?")
	}
	if renewalInfo.SuggestedWindow.End.Before(time.Now()) {
		t.Fatalf("suggested window start is in the past?")
	}
	if renewalInfo.SuggestedWindow.End.Before(renewalInfo.SuggestedWindow.Start) {
		t.Fatalf("suggested window end is before start?")
	}

	err = testClient.RevokeCertificate(account, certs[0], account.PrivateKey, ReasonUnspecified)
	if err != nil {
		t.Fatalf("failed to revoke certificate: %v", err)
	}

	// The renewal window should adjust to allow immediate renewal
	renewalInfo, err = testClient.GetRenewalInfo(certs[0])
	t.Logf("Suggested renewal window for revoked certificate: %v\n", renewalInfo.SuggestedWindow)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !renewalInfo.SuggestedWindow.Start.Before(time.Now()) {
		t.Fatalf("suggested window start is in the past?")
	}
	if !renewalInfo.SuggestedWindow.End.Before(time.Now()) {
		t.Fatalf("suggested window start is in the past?")
	}
	if renewalInfo.SuggestedWindow.End.Before(renewalInfo.SuggestedWindow.Start) {
		t.Fatalf("suggested window end is before start?")
	}
}

func TestClient_IssueReplacementCert(t *testing.T) {
	t.Log("Issuing initial order")
	account, order, _ := makeOrderFinalised(t, nil)
	if order.Certificate == "" {
		t.Fatalf("no certificate: %+v", order)
	}

	// Replacing the original order should work
	t.Log("Issuing first replacement order")
	replacementOrder1, err := makeReplacementOrderFinalized(t, order, account, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Replacing the replacement should work
	t.Log("Issuing second replacement order")
	_, err = makeReplacementOrderFinalized(t, replacementOrder1, account, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Attempting to replace a previously replaced order should fail
	t.Log("Should not be able to create a duplicate replacement")
	_, err = makeReplacementOrderFinalized(t, replacementOrder1, account, nil)
	if err == nil {
		t.Fatal(err)
	}
}

func Test_generateCertID(t *testing.T) {
	type args struct {
		cert *x509.Certificate
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "ari example",
			args: args{
				// certificate taken from draft-ietf-acme-ari-03 appendix A.1. Example Certificate
				cert: pem2cert(t, `-----BEGIN CERTIFICATE-----
MIIBQzCB66ADAgECAgUAh2VDITAKBggqhkjOPQQDAjAVMRMwEQYDVQQDEwpFeGFt
cGxlIENBMCIYDzAwMDEwMTAxMDAwMDAwWhgPMDAwMTAxMDEwMDAwMDBaMBYxFDAS
BgNVBAMTC2V4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeBZu
7cbpAYNXZLbbh8rNIzuOoqOOtmxA1v7cRm//AwyMwWxyHz4zfwmBhcSrf47NUAFf
qzLQ2PPQxdTXREYEnKMjMCEwHwYDVR0jBBgwFoAUaYhba4dGQEHhs3uEe6CuLN4B
yNQwCgYIKoZIzj0EAwIDRwAwRAIge09+S5TZAlw5tgtiVvuERV6cT4mfutXIlwTb
+FYN/8oCIClDsqBklhB9KAelFiYt9+6FDj3z4KGVelYM5MdsO3pK
-----END CERTIFICATE-----`),
			},
			want:    `aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE`,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateARICertID(tt.args.cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateARICertID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GenerateARICertID() error\n got  = %v\n want = %v", got, tt.want)
			}
		})
	}
}

func pem2cert(t *testing.T, s string) *x509.Certificate {
	block, _ := pem.Decode([]byte(s))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("error parsing certificate: %v", err)
	}
	return cert
}

type zeroTimeNow struct{}

func (zeroTimeNow) Now() time.Time {
	return time.Time{}
}

func Test_parseRetryAfter(t *testing.T) {
	systemTime = zeroTimeNow{}

	currentTime := time.Now().Round(time.Second)
	currentTimeRFC1123 := currentTime.Format(time.RFC1123)

	type args struct {
		ra string
	}
	tests := []struct {
		name    string
		args    args
		want    time.Time
		wantErr bool
	}{
		{
			name: "simple",
			args: args{
				ra: "123",
			},
			want:    time.Time{}.Add(123 * time.Second),
			wantErr: false,
		},
		{
			name: "date",
			args: args{
				ra: "Wed, 21 Oct 2015 07:28:00 GMT",
			},
			want:    time.Date(2015, 10, 21, 7, 28, 0, 0, time.FixedZone("GMT", 0)),
			wantErr: false,
		},
		{
			name: "bad",
			args: args{
				ra: "hello, world",
			},
			want:    time.Time{},
			wantErr: true,
		},
		{
			name: "dynamic",
			args: args{
				ra: currentTimeRFC1123,
			},
			want:    currentTime,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRetryAfter(tt.args.ra)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseRetryAfter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !got.Equal(tt.want) {
				t.Errorf("parseRetryAfter() got = %v, want %v", got, tt.want)
			}
		})
	}
}
