package analysis

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/schmeister/cve/internal/constants"
)

type Analysis []GetAnalysis

type GetAnalysis struct {
	AnalysisState         string `json:"analysisState"`
	AnalysisJustification string `json:"analysisJustification"`
	AnalysisDetails       string `json:"analysisDetails"`
	AnalysisComments      []struct {
		Timestamp int64  `json:"timestamp"`
		Comment   string `json:"comment"`
		Commenter string `json:"commenter"`
	} `json:"analysisComments"`
	IsSuppressed bool `json:"isSuppressed"`
}

type PutAnalysis struct {
	Suppressed            bool   `json:"suppressed"`
	AnalysisState         string `json:"analysisState,omitempty"`
	AnalysisJustification string `json:"analysisJustification,omitempty"`
	Project               string `json:"project"`
	Vulnerability         string `json:"vulnerability"`
	Component             string `json:"component"`
	IsSuppressed          bool   `json:"isSuppressed,omitempty"`
	Comment               string `json:"comment,omitempty"`
	AnalysisDetails       string `json:"analysisDetails,omitempty"`
	AnalysisResponse      string `json:"analysisResponse,omitempty"`
}

func (putAnalysis PutAnalysis) Save(flags constants.Flags) {
	url := flags.Uri + "/api/v1/analysis"

	data, _ := json.Marshal(putAnalysis)

	req, err := http.NewRequest(
		http.MethodPut,
		url,
		bytes.NewBuffer(data),
	)
	if err != nil {
		log.Fatalf("error creating HTTP request: %v", err)
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("X-Api-Key", flags.ApiKey)
	req.Header.Add("content-type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("error sending HTTP request: %v", err)
	}

	responseBytes, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("error reading HTTP response body: %v", err)
	}

	newG := GetAnalysis{}
	json.Unmarshal(responseBytes, &newG)
}

func Get(flags constants.Flags) GetAnalysis {
	url := flags.Uri + "/api/v1/analysis?" +
		"project=" + flags.Project + "&" +
		"component=" + flags.Component + "&" +
		"vulnerability=" + flags.Vulnerability

	req, err := http.NewRequest(
		http.MethodGet,
		url,
		nil,
	)
	if err != nil {
		log.Fatalf("error creating HTTP request: %v", err)
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("X-Api-Key", flags.ApiKey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("error sending HTTP request: %v", err)
	}

	responseBytes, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("error reading HTTP response body: %v", err)
	}

	analysis := GetAnalysis{}
	json.Unmarshal(responseBytes, &analysis)

	return analysis
}
