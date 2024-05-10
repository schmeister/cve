package project

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/schmeister/cve/internal/constants"
)

type Projects []Project
type Child struct {
	Active                 bool   `json:"active"`
	Classifier             string `json:"classifier"`
	DirectDependencies     string `json:"directDependencies"`
	LastBomImport          int64  `json:"lastBomImport"`
	LastBomImportFormat    string `json:"lastBomImportFormat"`
	LastInheritedRiskScore int    `json:"lastInheritedRiskScore"`
	Metadata               struct {
	} `json:"metadata"`
	Name   string `json:"name"`
	Parent struct {
		Name    string `json:"name"`
		UUID    string `json:"uuid"`
		Version string `json:"version"`
	} `json:"parent"`
	UUID    string `json:"uuid"`
	Version string `json:"version"`
}

type Project1 struct {
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

type Project2 struct {
	Name               string `json:"name"`
	Version            string `json:"version"`
	Classifier         string `json:"classifier"`
	DirectDependencies string `json:"directDependencies"`
	UUID               string `json:"uuid"`
	Parent             struct {
		Name string `json:"name"`
		UUID string `json:"uuid"`
	} `json:"parent"`
	Children []struct {
		Name               string `json:"name"`
		Version            string `json:"version"`
		Classifier         string `json:"classifier"`
		DirectDependencies string `json:"directDependencies"`
		UUID               string `json:"uuid"`
		Parent             struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			UUID    string `json:"uuid"`
		} `json:"parent"`
		LastBomImport          int64  `json:"lastBomImport"`
		LastBomImportFormat    string `json:"lastBomImportFormat"`
		LastInheritedRiskScore int    `json:"lastInheritedRiskScore"`
		Active                 bool   `json:"active"`
		Metadata               struct {
		} `json:"metadata"`
	} `json:"children"`
	LastBomImport          int64  `json:"lastBomImport"`
	LastBomImportFormat    string `json:"lastBomImportFormat"`
	LastInheritedRiskScore int    `json:"lastInheritedRiskScore"`
	Active                 bool   `json:"active"`
	Metadata               struct {
	} `json:"metadata"`
	Versions []struct {
		UUID    string `json:"uuid"`
		Version string `json:"version"`
	} `json:"versions"`
	Metrics struct {
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

type Project struct {
	Active                 bool    `json:"active"`
	Children               []Child `json:"children"`
	Classifier             string  `json:"classifier"`
	LastBomImport          int64   `json:"lastBomImport"`
	LastBomImportFormat    string  `json:"lastBomImportFormat"`
	LastInheritedRiskScore int     `json:"lastInheritedRiskScore"`
	Metadata               struct {
	} `json:"metadata"`
	Metrics struct {
		Components                           int   `json:"components"`
		Critical                             int   `json:"critical"`
		FindingsAudited                      int   `json:"findingsAudited"`
		FindingsTotal                        int   `json:"findingsTotal"`
		FindingsUnaudited                    int   `json:"findingsUnaudited"`
		FirstOccurrence                      int64 `json:"firstOccurrence"`
		High                                 int   `json:"high"`
		InheritedRiskScore                   int   `json:"inheritedRiskScore"`
		LastOccurrence                       int64 `json:"lastOccurrence"`
		Low                                  int   `json:"low"`
		Medium                               int   `json:"medium"`
		PolicyViolationsAudited              int   `json:"policyViolationsAudited"`
		PolicyViolationsFail                 int   `json:"policyViolationsFail"`
		PolicyViolationsInfo                 int   `json:"policyViolationsInfo"`
		PolicyViolationsLicenseAudited       int   `json:"policyViolationsLicenseAudited"`
		PolicyViolationsLicenseTotal         int   `json:"policyViolationsLicenseTotal"`
		PolicyViolationsLicenseUnaudited     int   `json:"policyViolationsLicenseUnaudited"`
		PolicyViolationsOperationalAudited   int   `json:"policyViolationsOperationalAudited"`
		PolicyViolationsOperationalTotal     int   `json:"policyViolationsOperationalTotal"`
		PolicyViolationsOperationalUnaudited int   `json:"policyViolationsOperationalUnaudited"`
		PolicyViolationsSecurityAudited      int   `json:"policyViolationsSecurityAudited"`
		PolicyViolationsSecurityTotal        int   `json:"policyViolationsSecurityTotal"`
		PolicyViolationsSecurityUnaudited    int   `json:"policyViolationsSecurityUnaudited"`
		PolicyViolationsTotal                int   `json:"policyViolationsTotal"`
		PolicyViolationsUnaudited            int   `json:"policyViolationsUnaudited"`
		PolicyViolationsWarn                 int   `json:"policyViolationsWarn"`
		Suppressed                           int   `json:"suppressed"`
		Unassigned                           int   `json:"unassigned"`
		Vulnerabilities                      int   `json:"vulnerabilities"`
		VulnerableComponents                 int   `json:"vulnerableComponents"`
	} `json:"metrics"`
	Name   string `json:"name"`
	Parent struct {
		UUID string `json:"uuid"`
		Name string `json:"name"`
	} `json:"parent"`
	UUID     string `json:"uuid"`
	Version  string `json:"version"`
	Versions []struct {
		UUID    string `json:"uuid"`
		Version string `json:"version"`
	} `json:"versions"`
}

func GetProjects(flags constants.Flags) Projects {
	url := flags.Uri + "/api/v1/project/"

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

	comps := Projects{}
	json.Unmarshal(responseBytes, &comps)

	return comps
}

func GetProject(flags constants.Flags) Project {
	url := flags.Uri + "/api/v1/project/" + flags.Project

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

	project := Project{}
	json.Unmarshal(responseBytes, &project)

	return project
}

func Refresh(flags constants.Flags) {
	url := flags.Uri + "/api/v1/metrics/project/" + flags.Project + "/refresh"

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

	_, err = io.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("error reading HTTP response body: %v", err)
	}
}

func (projects Projects) ListProjects(flags constants.Flags) []string {
	roots := make([]Project, 0)
	projectMap := make(map[string]Project)

	for _, project := range projects {
		flags.Project = project.UUID
		project = GetProject(flags)

		if project.Parent.Name == "" && project.Parent.UUID == "" {
			roots = append(roots, project)
		}
		projectMap[project.UUID] = project
	}

	ums := []color.Attribute{color.FgHiYellow, color.FgHiMagenta, color.FgHiGreen}

	for idx, y := range roots {
		_, _, s := y.Walk("", projectMap)
		pos := idx%(len(ums))
		color.Set(ums[pos])
		fmt.Printf("%s", s)
		color.Unset()
	}

	s := make([]string, 0)
	/*
		for _, project := range projects {
			remaining := project.Metrics.Suppressed
			total := project.Metrics.FindingsTotal + project.Metrics.Suppressed

			if project.Metrics.Components > 0 {
				percent := 100.0 * float64(remaining) / float64(total)
				log.Printf("%-25s v%-7s %s {%5.1f%% (%d/%d)}\n", project.Name, project.Version, project.UUID, percent, remaining, total)
				s = append(s, project.Name)
			}
		}
	*/
	return s

}

func (project Project) Walk(pad string, projectMap map[string]Project) (int, int, string) {
	done := project.Metrics.Suppressed
	total := project.Metrics.FindingsTotal + project.Metrics.Suppressed

	// Sort Children
	family := project.Children
	sort.SliceStable(family, func(i, j int) bool {
		return family[i].Name < family[j].Name
	})
	
	var st string
	for _, y := range family {
		p := projectMap[y.UUID]
		d, t, s := p.Walk(pad+"  ", projectMap)
		done += d
		total += t
		st += s
	}
	percent := 100.0 * float64(done) / float64(total)
	//str := fmt.Sprintf("%s %5.1f%%\n%s", pad+project.Name, percent, st)
	str := fmt.Sprintf("%-25.25s v%-7s %s {%5.1f%% (%d/%d)}\n%s", pad+project.Name, project.Version, project.UUID, percent, done, total, st)

	return done, total, str
}

func (projects Projects) GetProjectFromName(name string) Project {
	for _, project := range projects {
		if project.Name == name {
			return project
		}
	}
	return Project{}
}

func (projects Projects) GetProjectFromUUID(uuid string) Project {
	for _, project := range projects {
		if project.UUID == uuid {
			return project
		}
	}
	return Project{}
}

func (projects Projects) GetProject(name string) Project {
	for _, project := range projects {
		if project.Name == name {
			return project
		}
	}
	return Project{}
}
