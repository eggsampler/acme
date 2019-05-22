package acme

import (
	"net/http"
	"reflect"
	"testing"
)

func TestNewClient(t *testing.T) {
	if _, err := NewClient("http://fake"); err == nil {
		t.Fatal("expected error, got none")
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

func TestClient_Directory(t *testing.T) {
	if !reflect.DeepEqual(testClient.dir, testClient.Directory()) {
		t.Fatalf("directory mismatch, expected: %+v, got: %+v", testClient.dir, testClient.Directory())
	}
}
