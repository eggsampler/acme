package autocert

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/eggsampler/acme"
)

func TestWhitelistHosts(t *testing.T) {
	w := WhitelistHosts("hello")

	if err := w("no"); err == nil {
		t.Fatal("expected error, got none")
	}

	if err := w("hello"); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAutoCert_HTTPHandler(t *testing.T) {
	a := AutoCert{}
	handler := a.HTTPHandler(nil)
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Result().StatusCode != http.StatusMovedPermanently {
		t.Fatalf("expected status %d, got: %d", http.StatusMovedPermanently, w.Result().StatusCode)
	}
}

func TestAutoCert_GetCertificate(t *testing.T) {
	tests := []struct {
		ac     AutoCert
		helo   *tls.ClientHelloInfo
		err    bool
		errStr string
	}{
		{
			ac:     AutoCert{},
			helo:   &tls.ClientHelloInfo{},
			err:    true,
			errStr: "missing",
		},
		{
			ac:     AutoCert{},
			helo:   &tls.ClientHelloInfo{ServerName: "simple"},
			err:    true,
			errStr: "count invalid",
		},
		{
			ac:     AutoCert{},
			helo:   &tls.ClientHelloInfo{ServerName: `inva.lid\`},
			err:    true,
			errStr: "invalid character",
		},
		{
			ac:     AutoCert{},
			helo:   &tls.ClientHelloInfo{ServerName: `inva.lid/`},
			err:    true,
			errStr: "invalid character",
		},
		{
			ac:     AutoCert{HostCheck: WhitelistHosts("no.no")},
			helo:   &tls.ClientHelloInfo{ServerName: `va.lid`},
			err:    true,
			errStr: "not whitelisted",
		},
	}

	for _, test := range tests {
		_, err := test.ac.GetCertificate(test.helo)
		if test.err && err == nil {
			t.Fatalf("expected error, got none")
		}
		if !test.err && err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if !strings.Contains(err.Error(), test.errStr) {
			t.Fatalf("missing %q in error: %v", test.errStr, err)
		}
	}

}

func TestAutoCert_getDirectoryURL(t *testing.T) {
	ac := AutoCert{}
	if dir := ac.getDirectoryURL(); dir != acme.LetsEncryptStaging {
		t.Fatalf("Expected staging url, got: %s", dir)
	}
	ac.DirectoryURL = "blah"
	if dir := ac.getDirectoryURL(); dir != "blah" {
		t.Fatalf("expected blah, got: %s", dir)
	}
}

func TestAutoCert_Cache(t *testing.T) {
	ac := AutoCert{}
	data := []byte{1, 2, 3}
	ac.putCache(data, "hello", "world")
	if b := ac.getCache("hello", "world"); !reflect.DeepEqual(data, b) {
		t.Fatalf("expected: %+v, got: %+v", data, b)
	}

	if b := ac.getCache("non", "existent"); b != nil {
		t.Fatalf("expected: nil, got: %+v", b)
	}
}

func TestAutoCert_Cache2(t *testing.T) {
	ac := AutoCert{CacheDir: os.TempDir()}
	data := []byte{1, 2, 3}
	ctx := ac.putCache(data, "hello", "world")
	<-ctx.Done()

	ac2 := AutoCert{CacheDir: os.TempDir()}
	if b := ac2.getCache("hello", "world"); !reflect.DeepEqual(data, b) {
		t.Fatalf("expected: %+v, got: %+v", data, b)
	}

	ac3 := AutoCert{CacheDir: "fake"}
	if b := ac3.getCache("hello", "world"); b != nil {
		t.Fatalf("expected: nil, got: %+v", b)
	}
}

func TestAutoCert_checkHost(t *testing.T) {
	ac := AutoCert{}
	if err := ac.checkHost("ok"); err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}

	ac2 := AutoCert{HostCheck: WhitelistHosts("host")}
	if err := ac2.checkHost("ok"); err == nil {
		t.Fatal("expected error, got: nil")
	}
}

func TestAutoCert_getExistingCert(t *testing.T) {
	ac := AutoCert{}
	if cert := ac.getExistingCert("fake"); cert != nil {
		t.Fatalf("expected nil cert, got: %+v", cert)
	}
}

func TestAutoCert_GetCertificate2(t *testing.T) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := &http.Client{Transport: tr}
	resp, err := httpClient.Get("https://localhost:14000/root")
	if err != nil {
		t.Fatalf("error fetching root cert: %v", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("error reading root cert: %v", err)
	}

	doPost := func(name string, req interface{}) {
		reqJSON, err := json.Marshal(req)
		if err != nil {
			panic(fmt.Sprintf("error marshalling boulder %s: %v", name, err))
		}
		if _, err := http.Post("http://localhost:8055/"+name, "application/json", bytes.NewReader(reqJSON)); err != nil {
			panic(fmt.Sprintf("error posting boulder %s: %v", name, err))
		}
	}

	ac := AutoCert{
		DirectoryURL: "https://localhost:14000/dir",
		Options:      []acme.OptionFunc{acme.WithInsecureSkipVerify()},
		RootCert:     string(body),
		PreUpdateChallengeHook: func(account acme.Account, challenge acme.Challenge) {
			addReq := struct {
				Token   string `json:"token"`
				Content string `json:"content"`
			}{
				Token:   challenge.Token,
				Content: challenge.KeyAuthorization,
			}
			doPost("add-http01", addReq)
		},
	}

	cert, err := ac.GetCertificate(&tls.ClientHelloInfo{ServerName: "test.com"})
	if err != nil {
		t.Fatalf("error getting certificate: %v", err)
	}

	if cert == nil {
		t.Fatalf("NO CERT")
	}

}
