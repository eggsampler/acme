package acme

import (
	"math/rand"
	"reflect"
	"testing"
	"time"
)

const (
	testDirectoryUrl = "http://localhost:4001/directory" // boulder
	// testDirectoryUrl = "https://localhost:14000/dir" // pebble
	// testDirectoryUrl = "https://acme-staging-v02.api.letsencrypt.org/directory" lets encrypt acme v2
)

var client AcmeClient

func init() {
	rand.Seed(time.Now().UnixNano())
	var err error
	client, err = NewClient(testDirectoryUrl)
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

	if client.dir.NewAccount == "" {
		t.Fatalf("error creating new client: no new account url provided")
	}
}

func TestParseLinks(t *testing.T) {
	linkTests := []struct {
		Name  string
		Link  []string
		Count int
		Links map[string]string
	}{
		{"no links", []string{}, 0, nil},
		{"joined links", []string{`<https://url/path>; rel="next", <http://url/path?query>; rel="up"`}, 2, map[string]string{
			"next": "https://url/path",
			"up":   "http://url/path?query",
		}},
		{"separate links", []string{`<https://url/path>; rel="next"`, `<http://url/path?query>; rel="up"`}, 2, map[string]string{
			"next": "https://url/path",
			"up":   "http://url/path?query",
		}},
	}
	for _, currentTest := range linkTests {
		links := parseLinks(currentTest.Link)
		if len(links) != currentTest.Count {
			t.Fatalf("%s: expected %d links, got: %d", currentTest.Name, currentTest.Count, len(links))
		}
		if !reflect.DeepEqual(currentTest.Links, links) {
			t.Fatalf("%s: links not equal, expected: %+v, got: %+v", currentTest.Name, currentTest.Links, links)
		}
	}
}
