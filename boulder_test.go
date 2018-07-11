package acme

import (
	"bytes"
	"encoding/json"
	"net/http"
)

func newBoulderClient() testClientType {
	c, err := NewClient("http://localhost:4001/directory")
	if err != nil {
		panic("error creating boulder test client: " + err.Error())
	}
	return testClientType{
		Client: c,
		preChallenge: func(auth Authorization, chal Challenge) {
			switch chal.Type {
			case ChallengeTypeDNS01:
				setReq := struct {
					Host  string `json:"host"`
					Value string `json:"value"`
				}{
					Host:  "_acme-challenge." + auth.Identifier.Value + ".",
					Value: EncodeDNS01KeyAuthorization(chal.KeyAuthorization),
				}
				setReqJSON, err := json.Marshal(setReq)
				if err != nil {
					panic("error marshalling boulder set-text: " + err.Error())
				}
				if _, err := http.Post("http://localhost:8055/set-txt", "application/json", bytes.NewReader(setReqJSON)); err != nil {
					panic("error posting boulder set-text: " + err.Error())
				}

			case ChallengeTypeHTTP01:
				addReq := struct {
					Token   string `json:"token"`
					Content string `json:"content"`
				}{
					Token:   chal.Token,
					Content: chal.KeyAuthorization,
				}
				addReqJSON, err := json.Marshal(addReq)
				if err != nil {
					panic("error marshalling boulder add-http01: " + err.Error())
				}
				if _, err := http.Post("http://localhost:8055/add-http01", "application/json", bytes.NewReader(addReqJSON)); err != nil {
					panic("error posting boulder add-http01: " + err.Error())
				}

			case ChallengeTypeTLSALPN01:
				addReq := struct {
					Host    string `json:"host"`
					Content string `json:"content"`
				}{
					Host:    auth.Identifier.Value,
					Content: chal.KeyAuthorization,
				}
				addReqJSON, err := json.Marshal(addReq)
				if err != nil {
					panic("error marshalling boulder add-tlsalpn01: " + err.Error())
				}
				if _, err := http.Post("http://localhost:8055/add-tlsalpn01", "application/json", bytes.NewReader(addReqJSON)); err != nil {
					panic("error posting boulder add-tlsalpn01: " + err.Error())
				}

			default:
				panic("pre: unsupported challenge type: " + chal.Type)
			}
		},
		postChallenge: func(auth Authorization, chal Challenge) {
			switch chal.Type {
			case ChallengeTypeDNS01:
				host := "_acme-challenge." + auth.Identifier.Value + "."
				clearReq := struct {
					Host string `json:"host"`
				}{
					Host: host,
				}
				clearReqJSON, err := json.Marshal(clearReq)
				if err != nil {
					panic("error marshalling boulder clear-text: " + err.Error())
				}
				if _, err := http.Post("http://localhost:8055/clear-txt", "application/json", bytes.NewReader(clearReqJSON)); err != nil {
					panic("error posting boulder clear-text: " + err.Error())
				}

			case ChallengeTypeHTTP01:
				delReq := struct {
					Token string `json:"token"`
				}{
					Token: chal.Token,
				}
				delReqJSON, err := json.Marshal(delReq)
				if err != nil {
					panic("error marshalling boulder del-http01: " + err.Error())
				}
				if _, err := http.Post("http://localhost:8055/del-http01", "application/json", bytes.NewReader(delReqJSON)); err != nil {
					panic("error posting boulder del-http01: " + err.Error())
				}

			case ChallengeTypeTLSALPN01:
				delReq := struct {
					Host string `json:"token"`
				}{
					Host: auth.Identifier.Value,
				}
				delReqJSON, err := json.Marshal(delReq)
				if err != nil {
					panic("error marshalling boulder del-tlsalpn01: " + err.Error())
				}
				if _, err := http.Post("http://localhost:8055/del-tlsalpn01", "application/json", bytes.NewReader(delReqJSON)); err != nil {
					panic("error posting boulder del-tlsalpn01: " + err.Error())
				}

			default:
				panic("post: unsupported challenge type: " + chal.Type)
			}
		},
	}
}
