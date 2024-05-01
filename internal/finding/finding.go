package finding

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/schmeister/cve/internal/constants"
)

type Findings []Finding

type Finding struct {
	Component     Component     `json:"component"`    
	Vulnerability Vulnerability `json:"vulnerability"`
	Analysis      Analysis      `json:"analysis"`     
	Attribution   Attribution   `json:"attribution"`  
	Matrix        string        `json:"matrix"`       
}

type Analysis struct {
	IsSuppressed bool   `json:"isSuppressed"`   
	State        *State `json:"state,omitempty"`
}

type Attribution struct {
	AnalyzerIdentity AnalyzerIdentity `json:"analyzerIdentity"`
	AttributedOn     int64            `json:"attributedOn"`    
}

type Component struct {
	UUID    string `json:"uuid"`   
	Name    string `json:"name"`   
	Version string `json:"version"`
	Cpe     string `json:"cpe"`    
	Project string `json:"project"`
}

type Vulnerability struct {
	UUID            string        `json:"uuid"`                     
	Source          Source        `json:"source"`                   
	VulnID          string        `json:"vulnId"`                   
	CvssV3BaseScore *float64      `json:"cvssV3BaseScore,omitempty"`
	Severity        Severity      `json:"severity"`                 
	SeverityRank    int64         `json:"severityRank"`             
	EpssScore       float64       `json:"epssScore"`                
	EpssPercentile  float64       `json:"epssPercentile"`           
	CweID           *int64        `json:"cweId,omitempty"`          
	CweName         *string       `json:"cweName,omitempty"`        
	Cwes            []Cwe         `json:"cwes,omitempty"`           
	Aliases         []interface{} `json:"aliases"`                  
	Description     string        `json:"description"`              
	Recommendation  interface{}   `json:"recommendation"`           
	CvssV2BaseScore *float64      `json:"cvssV2BaseScore,omitempty"`
}

type Cwe struct {
	CweID int64  `json:"cweId"`
	Name  string `json:"name"` 
}

type State string
const (
	NotAffected State = "NOT_AFFECTED"
	NotSet State = "NOT_SET"
)

type AnalyzerIdentity string
const (
	InternalAnalyzer AnalyzerIdentity = "INTERNAL_ANALYZER"
)

type Severity string
const (
	Critical Severity = "CRITICAL"
	High Severity = "HIGH"
	Low Severity = "LOW"
	Medium Severity = "MEDIUM"
)

type Source string
const (
	Nvd Source = "NVD"
)


func GetFindings(flags constants.Flags) Findings {
	url := flags.Uri + "/api/v1/finding/project/" +
		flags.Project +
		"?suppressed=true"

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

	findings := Findings{}
	json.Unmarshal(responseBytes, &findings)

	return findings
}