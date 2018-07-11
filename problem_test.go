package acme

import (
	"net/http"
	"strings"
	"testing"
)

func TestCheckError(t *testing.T) {
	errorTests := []struct {
		Name           string
		URL            string
		ExpectedStatus []int
	}{
		{
			Name:           "test expecting http 202, but got 200",
			URL:            testClient.Directory().URL,
			ExpectedStatus: []int{202},
		},
		{
			Name:           "test acme error expecting ok",
			URL:            testClient.Directory().NewAccount,
			ExpectedStatus: []int{http.StatusOK},
		},
		{
			Name:           "test http error expecting ok",
			URL:            testClient.Directory().NewAccount + "/asdasdasdasdasd",
			ExpectedStatus: []int{http.StatusOK},
		},
	}
	for _, currentTest := range errorTests {
		resp, err := http.Get(currentTest.URL)
		if err != nil {
			t.Fatalf("error %s: expected no error, got: %v", currentTest.Name, err)
		}
		if err := checkError(resp, currentTest.ExpectedStatus...); err == nil {
			t.Fatalf("error %s: expected error, got none", currentTest.Name)
		}
	}

	resp, err := http.Get(testClient.Directory().URL)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if err := checkError(resp, http.StatusOK); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestProblem_Error(t *testing.T) {
	err := Problem{}
	s := error(err).Error()
	if !strings.HasPrefix(s, "acme: error code") {
		t.Fatalf("unexpected acme error: %v", err)
	}
}
