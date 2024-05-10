package components

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/schmeister/cve/internal/constants"
)
package components

type Components []Component
type CMap map[string]Component

type Component struct {
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

func GetProjectComponents(flags constants.Flags) (Components, CMap) {
	page := 1
	pageSize := 200
	components := Components{}
	hasMore := true

	for hasMore {

		url := flags.Uri + "/api/v1/component/project/" + flags.Project +
			"?onlyOutdated=false&onlyDirect=false" +
			"&pageNumber=" + fmt.Sprintf("%d", page) +
			"&pageSize=" + fmt.Sprintf("%d", pageSize)

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
		components = append(components, comps...)

		if len(comps) < pageSize {
			break
		}
		page++
	}

	cMap := make(CMap)
	for _, y := range components {
		cMap[y.Name+y.Version] = y
	}

	return components, cMap
}

func GetComponentFromUUID(flags constants.Flags) Component {
	component := Component{}
	hasMore := true

	for hasMore {

		url := flags.Uri + "/api/v1/component/" + flags.Component

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

		json.Unmarshal(responseBytes, &component)
	}
	return component
}

func (components Components) GetComponentsFromName(flags constants.Flags) Components {
	if flags.Component == "" {
		return components
	}

	comps := make(Components, 0)

	for _, comp := range components {
		if strings.EqualFold(comp.Name, flags.Component) {
			comps = append(comps, comp)
		}
	}
	return comps
}

func (components CMap) GetComponentsFromName(flags constants.Flags) CMap {
	if flags.Component == "" {
		return components
	}

	comps := make(CMap, 0)

	for _, comp := range components {
		if strings.EqualFold(comp.Name, flags.Component) {
			comps[comp.Name] = comp
		}
	}
	return comps
}

func (components Components) ListComponents(flags constants.Flags) {
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgHiRed).SprintFunc()
	blue := color.New(color.FgHiBlue).SprintFunc()

	projects := project.GetProjects(flags)
	project := projects.GetProjectFromUUID(flags.Project)

	log.Printf("%-25s%20s(%s)\n", red(project.Name), "", project.UUID)
	for _, component := range components {
		log.Printf("%-25s%-20s(%s)\n", yellow(component.Name), blue(component.Version), component.UUID)
	}
}

func (cmap CMap) ListComponents(flags constants.Flags) {
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgHiRed).SprintFunc()
	blue := color.New(color.FgHiBlue).SprintFunc()

	projects := project.GetProjects(flags)
	project := projects.GetProjectFromUUID(flags.Project)

	log.Printf("%-25s%20s(%s)\n", red(project.Name), "", project.UUID)
	for _, component := range cmap {
		log.Printf("%-25s%-20s(%s)\n", yellow(component.Name), blue(component.Version), component.UUID)
	}
}

func (vuls CMap) Sort() []string {

	keys := make([]string, 0, len(vuls))
	for k := range vuls {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
