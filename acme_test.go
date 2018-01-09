package acme

import (
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"testing"
	"time"
)

const (
	testDirectoryUrl = "http://localhost:4001/directory" // boulder
	// testDirectoryUrl = "https://localhost:14000/dir" // pebble
	// testDirectoryUrl = "https://acme-staging-v02.api.letsencrypt.org/directory" lets encrypt acme v2
)

var testClient AcmeClient

func init() {
	rand.Seed(time.Now().UnixNano())
	var err error
	Debug = true
	log.SetOutput(ioutil.Discard)
	testClient, err = NewClient(testDirectoryUrl)
	if err != nil {
		panic("error connecting to acme server: " + err.Error())
	}
}

func randString() string {
	min := int('a')
	max := int('z')
	n := rand.Intn(10) + 10
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = byte(rand.Intn(max-min) + min)
	}
	return string(b)
}

func TestNewClient(t *testing.T) {
	if _, err := NewClient("http://fake"); err == nil {
		t.Fatalf("expected error, got none")
	}

	if testClient.dir.NewAccount == "" {
		t.Fatalf("error creating new client: no new account url provided")
	}
}

func TestParseLinks(t *testing.T) {
	linkTests := []struct {
		Name        string
		LinkHeaders []string
		WantedLink  string
		ExpectedUrl string
	}{
		{
			Name:        "no links",
			WantedLink:  "fail",
			ExpectedUrl: "",
		},
		{Name: "joined links",
			LinkHeaders: []string{`<https://url/path>; rel="next", <http://url/path?query>; rel="up"`},
			WantedLink:  "up",
			ExpectedUrl: "http://url/path?query",
		},
		{
			Name:        "separate links",
			LinkHeaders: []string{`<https://url/path>; rel="next"`, `<http://url/path?query>; rel="up"`},
			WantedLink:  "up",
			ExpectedUrl: "http://url/path?query",
		},
	}
	for _, currentTest := range linkTests {
		linkUrl := fetchLink(&http.Response{Header: http.Header{"Link": currentTest.LinkHeaders}}, currentTest.WantedLink)
		if linkUrl != currentTest.ExpectedUrl {
			t.Fatalf("%s: links not equal, expected: %s, got: %s", currentTest.Name, currentTest.ExpectedUrl, linkUrl)
		}
	}
}
