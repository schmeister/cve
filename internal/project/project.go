package project

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
)

type Projects []struct {
	Name                   string `json:"name"`
	Version                string `json:"version"`
	Classifier             string `json:"classifier"`
	DirectDependencies     string `json:"directDependencies"`
	UUID                   string `json:"uuid"`
	LastBomImport          int64  `json:"lastBomImport"`
	LastBomImportFormat    string `json:"lastBomImportFormat"`
	LastInheritedRiskScore int    `json:"lastInheritedRiskScore"`
	Active                 bool   `json:"active"`
	Metrics                struct {
		Critical                             int   `json:"critical"`
		High                                 int   `json:"high"`
		Medium                               int   `json:"medium"`
		Low                                  int   `json:"low"`
		Unassigned                           int   `json:"unassigned"`
		Vulnerabilities                      int   `json:"vulnerabilities"`
		VulnerableComponents                 int   `json:"vulnerableComponents"`
		Components                           int   `json:"components"`
		Suppressed                           int   `json:"suppressed"`
		FindingsTotal                        int   `json:"findingsTotal"`
		FindingsAudited                      int   `json:"findingsAudited"`
		FindingsUnaudited                    int   `json:"findingsUnaudited"`
		InheritedRiskScore                   int   `json:"inheritedRiskScore"`
		PolicyViolationsFail                 int   `json:"policyViolationsFail"`
		PolicyViolationsWarn                 int   `json:"policyViolationsWarn"`
		PolicyViolationsInfo                 int   `json:"policyViolationsInfo"`
		PolicyViolationsTotal                int   `json:"policyViolationsTotal"`
		PolicyViolationsAudited              int   `json:"policyViolationsAudited"`
		PolicyViolationsUnaudited            int   `json:"policyViolationsUnaudited"`
		PolicyViolationsSecurityTotal        int   `json:"policyViolationsSecurityTotal"`
		PolicyViolationsSecurityAudited      int   `json:"policyViolationsSecurityAudited"`
		PolicyViolationsSecurityUnaudited    int   `json:"policyViolationsSecurityUnaudited"`
		PolicyViolationsLicenseTotal         int   `json:"policyViolationsLicenseTotal"`
		PolicyViolationsLicenseAudited       int   `json:"policyViolationsLicenseAudited"`
		PolicyViolationsLicenseUnaudited     int   `json:"policyViolationsLicenseUnaudited"`
		PolicyViolationsOperationalTotal     int   `json:"policyViolationsOperationalTotal"`
		PolicyViolationsOperationalAudited   int   `json:"policyViolationsOperationalAudited"`
		PolicyViolationsOperationalUnaudited int   `json:"policyViolationsOperationalUnaudited"`
		FirstOccurrence                      int64 `json:"firstOccurrence"`
		LastOccurrence                       int64 `json:"lastOccurrence"`
	} `json:"metrics"`
}

func GetProjects(uri string, apikey string) Projects {
	url := uri + "/api/v1/project/"

	req, err := http.NewRequest(
		http.MethodGet,
		url,
		nil,
	)
	if err != nil {
		log.Fatalf("error creating HTTP request: %v", err)
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("X-Api-Key", apikey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("error sending HTTP request: %v", err)
	}

	responseBytes, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("error reading HTTP response body: %v", err)
	}

	comps := Projects{}
	json.Unmarshal(responseBytes, &comps)

	return comps
}

func (projects Projects) ListProjects() {
	for _, project := range projects {
		log.Printf("%-10s %s\n", project.Name, project.UUID)
	}
}