package acme

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"testing"
	"time"
)

func TestClient_GetRenewalInfo(t *testing.T) {
	if testClientMeta.Software == clientPebble {
		t.Skip("pebble doesnt support ari")
		return
	}

	account, order, _ := makeOrderFinalised(t, nil)
	if order.Certificate == "" {
		t.Fatalf("no certificate: %+v", order)
	}
	certs, err := testClient.FetchCertificates(account, order.Certificate)
	if err != nil {
		t.Fatalf("expeceted no error, got: %v", err)
	}
	if len(certs) < 2 {
		t.Fatalf("no certs")
	}
	renewalInfo, err := testClient.GetRenewalInfo(certs[0], certs[1], crypto.SHA256)
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
}

func TestClient_UpdateRenewalInfo(t *testing.T) {
	if testClientMeta.Software == clientPebble {
		t.Skip("pebble doesnt support ari")
		return
	}

	account, order, _ := makeOrderFinalised(t, nil)
	if order.Certificate == "" {
		t.Fatalf("no certificate: %+v", order)
	}
	certs, err := testClient.FetchCertificates(account, order.Certificate)
	if err != nil {
		t.Fatalf("expeceted no error, got: %v", err)
	}
	if len(certs) < 2 {
		t.Fatalf("no certs")
	}
	if err := testClient.UpdateRenewalInfo(account, certs[0], certs[1], crypto.SHA256, true); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	// TODO: update this test once there's any feedback or change in the renewal info provided by boulder?
	// as of 2023-04-09, it appears to be the same before updating, and after updating
}

func Test_generateCertID(t *testing.T) {
	type args struct {
		cert     *x509.Certificate
		issuer   *x509.Certificate
		hashFunc crypto.Hash
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
				// certificate taken from draft-ietf-acme-ari-01 appendix A.1. Example End-Entity Certificate
				cert: pem2cert(t, `-----BEGIN CERTIFICATE-----
MIIDMDCCAhigAwIBAgIIPqNFaGVEHxwwDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
AxMVbWluaWNhIHJvb3QgY2EgM2ExMzU2MB4XDTIyMDMxNzE3NTEwOVoXDTI0MDQx
NjE3NTEwOVowFjEUMBIGA1UEAxMLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCgm9K/c+il2Pf0f8qhgxn9SKqXq88cOm9ov9AVRbPA
OWAAewqX2yUAwI4LZBGEgzGzTATkiXfoJ3cN3k39cH6tBbb3iSPuEn7OZpIk9D+e
3Q9/hX+N/jlWkaTB/FNA+7aE5IVWhmdczYilXa10V9r+RcvACJt0gsipBZVJ4jfJ
HnWJJGRZzzxqG/xkQmpXxZO7nOPFc8SxYKWdfcgp+rjR2ogYhSz7BfKoVakGPbpX
vZOuT9z4kkHra/WjwlkQhtHoTXdAxH3qC2UjMzO57Tx+otj0CxAv9O7CTJXISywB
vEVcmTSZkHS3eZtvvIwPx7I30ITRkYk/tLl1MbyB3SiZAgMBAAGjeDB2MA4GA1Ud
DwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0T
AQH/BAIwADAfBgNVHSMEGDAWgBQ4zzDRUaXHVKqlSTWkULGU4zGZpTAWBgNVHREE
DzANggtleGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAx0aYvmCk7JYGNEXe
+hrOfKawkHYzWvA92cI/Oi6h+oSdHZ2UKzwFNf37cVKZ37FCrrv5pFP/xhhHvrNV
EnOx4IaF7OrnaTu5miZiUWuvRQP7ZGmGNFYbLTEF6/dj+WqyYdVaWzxRqHFu1ptC
TXysJCeyiGnR+KOOjOOQ9ZlO5JUK3OE4hagPLfaIpDDy6RXQt3ss0iNLuB1+IOtp
1URpvffLZQ8xPsEgOZyPWOcabTwJrtqBwily+lwPFn2mChUx846LwQfxtsXU/lJg
HX2RteNJx7YYNeX3Uf960mgo5an6vE8QNAsIoNHYrGyEmXDhTRe9mCHyiW2S7fZq
o9q12g==
-----END CERTIFICATE-----`),
				// certificate taken from draft-ietf-acme-ari-01 appendix A.2. Example CA Certificate
				issuer: pem2cert(t, `-----BEGIN CERTIFICATE-----
MIIDSzCCAjOgAwIBAgIIOhNWtJ7Igr0wDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
AxMVbWluaWNhIHJvb3QgY2EgM2ExMzU2MCAXDTIyMDMxNzE3NTEwOVoYDzIxMjIw
MzE3MTc1MTA5WjAgMR4wHAYDVQQDExVtaW5pY2Egcm9vdCBjYSAzYTEzNTYwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDc3P6cxcCZ7FQOQrYuigReSa8T
IOPNKmlmX9OrTkPwjThiMNEETYKO1ea99yXPK36LUHC6OLmZ9jVQW2Ny1qwQCOy6
TrquhnwKgtkBMDAZBLySSEXYdKL3r0jA4sflW130/OLwhstU/yv0J8+pj7eSVOR3
zJBnYd1AqnXHRSwQm299KXgqema7uwsa8cgjrXsBzAhrwrvYlVhpWFSv3lQRDFQg
c5Z/ZDV9i26qiaJsCCmdisJZWN7N2luUgxdRqzZ4Cr2Xoilg3T+hkb2y/d6ttsPA
kaSA+pq3q6Qa7/qfGdT5WuUkcHpvKNRWqnwT9rCYlmG00r3hGgc42D/z1VvfAgMB
AAGjgYYwgYMwDgYDVR0PAQH/BAQDAgKEMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr
BgEFBQcDAjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBQ4zzDRUaXHVKql
STWkULGU4zGZpTAfBgNVHSMEGDAWgBQ4zzDRUaXHVKqlSTWkULGU4zGZpTANBgkq
hkiG9w0BAQsFAAOCAQEArbDHhEjGedjb/YjU80aFTPWOMRjgyfQaPPgyxwX6Dsid
1i2H1x4ud4ntz3sTZZxdQIrOqtlIWTWVCjpStwGxaC+38SdreiTTwy/nikXGa/6W
ZyQRppR3agh/pl5LHVO6GsJz3YHa7wQhEhj3xsRwa9VrRXgHbLGbPOFVRTHPjaPg
Gtsv2PN3f67DsPHF47ASqyOIRpLZPQmZIw6D3isJwfl+8CzvlB1veO0Q3uh08IJc
fspYQXvFBzYa64uKxNAJMi4Pby8cf4r36Wnb7cL4ho3fOHgAltxdW8jgibRzqZpQ
   QKyxn2jX7kxeUDt0hFDJE8lOrhP73m66eBNzxe//FQ==
-----END CERTIFICATE-----`),
				hashFunc: crypto.SHA256,
			},
			want:    `MFswCwYJYIZIAWUDBAIBBCCeWLRusNLb--vmWOkxm34qDjTMWkc3utIhOMoMwKDqbgQg2iiKWySZrD-6c88HMZ6vhIHZPamChLlzGHeZ7pTS8jYCCD6jRWhlRB8c`,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := generateCertID(tt.args.cert, tt.args.issuer, tt.args.hashFunc)
			if (err != nil) != tt.wantErr {
				t.Errorf("generateCertID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("generateCertID() error\n got  = %v\n want = %v", got, tt.want)
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
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseRetryAfter() got = %v, want %v", got, tt.want)
			}
		})
	}
}
