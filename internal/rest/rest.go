package rest

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/schmeister/cve/internal/bom"
)

func GetBOM(uri string, apiKey string, project string) bom.BOM {
	url := uri + "/api/v1/bom/cyclonedx/project/" + project + "?download=false"

	req, err := http.NewRequest(
		http.MethodGet,
		url,
		nil,
	)
	if err != nil {
		log.Fatalf("error creating HTTP request: %v", err)
	}

	req.Header.Add("Accept", "application/vnd.cyclonedx+xml")
	req.Header.Add("X-Api-Key", apiKey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("error sending HTTP request: %v", err)
	}

	responseBytes, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("error reading HTTP response body: %v", err)
	}

	theBom := bom.BOM{}
	json.Unmarshal(responseBytes, &theBom)

	return theBom
}
func GetVEX(uri string, apiKey string, project string) bom.BOM {
	url := uri + "/api/v1/bom/cyclonedx/project/" + project + "?download=false"

	req, err := http.NewRequest(
		http.MethodGet,
		url,
		nil,
	)
	if err != nil {
		log.Fatalf("error creating HTTP request: %v", err)
	}

	req.Header.Add("Accept", "application/vnd.cyclonedx+xml")
	req.Header.Add("X-Api-Key", apiKey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("error sending HTTP request: %v", err)
	}

	responseBytes, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("error reading HTTP response body: %v", err)
	}

	theBom := bom.BOM{}
	json.Unmarshal(responseBytes, &theBom)

	return theBom
}
