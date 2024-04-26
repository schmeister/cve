package components

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"gheprivate.intra.corp/vss/cots-management/internal/constants"
)

type Components []struct {
	Name               string `json:"name"`
	Classifier         string `json:"classifier"`
	DirectDependencies string `json:"directDependencies,omitempty"`
	ExternalReferences []struct {
		Type    string `json:"type"`
		URL     string `json:"url"`
		Comment string `json:"comment"`
	} `json:"externalReferences,omitempty"`
	Project struct {
		Name                   string `json:"name"`
		Version                string `json:"version"`
		Classifier             string `json:"classifier"`
		DirectDependencies     string `json:"directDependencies"`
		UUID                   string `json:"uuid"`
		LastBomImport          int64  `json:"lastBomImport"`
		LastBomImportFormat    string `json:"lastBomImportFormat"`
		LastInheritedRiskScore int    `json:"lastInheritedRiskScore"`
		Active                 bool   `json:"active"`
	} `json:"project"`
	LastInheritedRiskScore int    `json:"lastInheritedRiskScore"`
	UUID                   string `json:"uuid"`
	Metrics                struct {
		Critical                             int   `json:"critical"`
		High                                 int   `json:"high"`
		Medium                               int   `json:"medium"`
		Low                                  int   `json:"low"`
		Unassigned                           int   `json:"unassigned"`
		Vulnerabilities                      int   `json:"vulnerabilities"`
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
	UsedBy                int  `json:"usedBy"`
	ExpandDependencyGraph bool `json:"expandDependencyGraph"`
	IsInternal            bool `json:"isInternal"`
	Supplier              struct {
		Name string `json:"name"`
	} `json:"supplier,omitempty"`
	Version string `json:"version,omitempty"`
	Cpe     string `json:"cpe,omitempty"`
}

func GetComponents(flags constants.Flags) Components {
	url := flags.Uri + "/api/v1/component/project/" + flags.Project + "?onlyOutdated=false&onlyDirect=false"

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

	comps := Components{}
	json.Unmarshal(responseBytes, &comps)

	return comps
}

func GetComponent(flags constants.Flags, components Components) []string {
	uuids := make([]string,0)
	for _, y := range components {
		if strings.EqualFold(y.Name, flags.Component) {
			uuids = append(uuids, y.UUID)
		}
	}
	return uuids
}

func (components Components) ListComponents() {
	for _, component := range components {
		log.Printf("%-25s %s\n", component.Name, component.UUID)
	}
}
