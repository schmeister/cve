package rest

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/schmeister/cve/internal/bom"
)

func GetBOM(project string) bom.BOM {
	url := "http://localhost:8081/api/v1/bom/cyclonedx/project/923e19be-0680-479a-9881-7a731df672c3?download=false"

	req, err := http.NewRequest(
		http.MethodGet,
		url,
		nil,
	)
	if err != nil {
		log.Fatalf("error creating HTTP request: %v", err)
	}

	req.Header.Add("Accept", "application/vnd.cyclonedx+xml")
	req.Header.Add("X-Api-Key", "odt_9SzIIWOMDrMm8IYwjVqZX8IBW90ppCCU")

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
func GetVEX(project string) bom.BOM {
	url := "http://localhost:8081/api/v1/bom/cyclonedx/project/923e19be-0680-479a-9881-7a731df672c3?download=false"

	req, err := http.NewRequest(
		http.MethodGet,
		url,
		nil,
	)
	if err != nil {
		log.Fatalf("error creating HTTP request: %v", err)
	}

	req.Header.Add("Accept", "application/vnd.cyclonedx+xml")
	req.Header.Add("X-Api-Key", "odt_9SzIIWOMDrMm8IYwjVqZX8IBW90ppCCU")

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
