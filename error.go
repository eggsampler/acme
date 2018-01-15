package acme

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type AcmeError struct {
	Status      int    `json:"status"`
	Type        string `json:"type"`
	Detail      string `json:"detail"`
	Instance    string `json:"instance"`
	SubProblems []struct {
		Type       string `json:"type"`
		Detail     string `json:"detail"`
		Identifier AcmeIdentifier
	} `json:"subproblems"`
}

func (err AcmeError) Error() string {
	s := fmt.Sprintf("acme: error code %d %q: %s", err.Status, err.Type, err.Detail)
	if len(err.SubProblems) > 0 {
		for _, v := range err.SubProblems {
			s += fmt.Sprintf(", problem %q: %s", v.Type, v.Detail)
		}
	}
	if err.Instance != "" {
		s += ", url: " + err.Instance
	}
	return s
}

func checkError(resp *http.Response, expectedStatuses ...int) error {
	for _, statusCode := range expectedStatuses {
		if resp.StatusCode == statusCode {
			return nil
		}
	}

	if resp.StatusCode < 400 || resp.StatusCode >= 600 {
		return fmt.Errorf("acme: expected status codes: %d, got: %d %s", expectedStatuses, resp.StatusCode, resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("acme: error reading error body: %v", err)
	}

	acmeError := AcmeError{}
	if err := json.Unmarshal(body, &acmeError); err != nil {
		return fmt.Errorf("acme: parsing error body: %v - %s", err, string(body))
	}

	return acmeError
}
