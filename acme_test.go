package acme

import (
	"math/rand"
	"net/http"
	"testing"
	"time"
)

const (
	testDirectoryURL = "http://localhost:4001/directory" // boulder
)

var testClient Client

func init() {
	rand.Seed(time.Now().UnixNano())
	var err error
	testClient, err = NewClient(testDirectoryURL)
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

	if testClient.Directory.NewAccount == "" {
		t.Fatalf("error creating new client: no new account url provided")
	}
}

func TestParseLinks(t *testing.T) {
	linkTests := []struct {
		Name        string
		LinkHeaders []string
		WantedLink  string
		ExpectedURL string
	}{
		{
			Name:        "no links",
			WantedLink:  "fail",
			ExpectedURL: "",
		},
		{Name: "joined links",
			LinkHeaders: []string{`<https://url/path>; rel="next", <http://url/path?query>; rel="up"`},
			WantedLink:  "up",
			ExpectedURL: "http://url/path?query",
		},
		{
			Name:        "separate links",
			LinkHeaders: []string{`<https://url/path>; rel="next"`, `<http://url/path?query>; rel="up"`},
			WantedLink:  "up",
			ExpectedURL: "http://url/path?query",
		},
	}
	for _, currentTest := range linkTests {
		linkURL := fetchLink(&http.Response{Header: http.Header{"Link": currentTest.LinkHeaders}}, currentTest.WantedLink)
		if linkURL != currentTest.ExpectedURL {
			t.Fatalf("%s: links not equal, expected: %s, got: %s", currentTest.Name, currentTest.ExpectedURL, linkURL)
		}
	}
}
