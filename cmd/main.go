package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"slices"
	"strings"
	"time"
)

type Analysis struct {
	State         string `json:"state,omitempty"`
	Justification string `json:"justification,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

type Vulnerability struct {
	BomRef string `json:"bom-ref"`
	ID     string `json:"id"`
	Source struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"source"`
	Ratings []struct {
		Source struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"source"`
		Score    float64 `json:"score"`
		Severity string  `json:"severity"`
		Method   string  `json:"method"`
		Vector   string  `json:"vector"`
	} `json:"ratings"`
	Cwes        []int     `json:"cwes,omitempty"`
	Description string    `json:"description"`
	Published   time.Time `json:"published"`
	Updated     time.Time `json:"updated"`
	Analysis    Analysis  `json:"analysis,omitempty"`
	Affects     []struct {
		Ref string `json:"ref"`
	} `json:"affects"`
}

type Vex struct {
	BomFormat    string `json:"bomFormat"`
	SpecVersion  string `json:"specVersion"`
	SerialNumber string `json:"serialNumber"`
	Version      int    `json:"version"`
	Metadata     struct {
		Timestamp time.Time `json:"timestamp"`
		Tools     []struct {
			Vendor  string `json:"vendor"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"tools"`
		Component struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
			BomRef  string `json:"bom-ref"`
		} `json:"component"`
	} `json:"metadata"`
	Components []struct {
		Supplier struct {
			Name string `json:"name"`
		} `json:"supplier"`
		Name    string `json:"name"`
		Version string `json:"version"`
		Cpe     string `json:"cpe"`
		Type    string `json:"type"`
		BomRef  string `json:"bom-ref"`
	} `json:"components,omitempty"`
	Dependencies []struct {
		Ref       string `json:"ref"`
		DependsOn []any  `json:"dependsOn"`
	} `json:"dependencies,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

func main() {

	keyPtr := flag.String("key", "", "Label to be searched")
	statePtr := flag.String("state", "", "new state")
	justificationPtr := flag.String("just", "", "justification")
	detailsPtr := flag.String("details", "", "details")
	flag.Parse()

	valid := validate(keyPtr, statePtr, justificationPtr, detailsPtr)

	if valid {
		vex := unmarshal("/home/fedora/Downloads/vex.json")
		bom := unmarshal("/home/fedora/Downloads/bom.json")

		bomRef := getBomRef(bom, keyPtr)
		fmt.Printf("%s(\x1b[%dm%s\x1b[0m)\n", bomRef, 34, *keyPtr)

		vex = setAnalysis(vex, bomRef, keyPtr, statePtr, justificationPtr, detailsPtr)

		write(vex)
	}
}

func validate(keyPtr, statePtr, justificationPtr, detailsPtr *string) bool {
	var state = []string{"not_set", "exploitable", "in_triage", "resolved",
		"false_positive", "not_affected"}
	var justification = []string{"not_set", "code_not_present", "code_not_reachable",
		"requires_configuration", "requires_dependency", "requires_environment",
		"protected_by_compiler", "protected_at_runtine", "protected_at_perimeter",
		"protected_by_mitigating_control"}

	valid := true
	if len(*keyPtr) < 3 {
		valid = false
	}
	if len(*statePtr) == 0 || !slices.Contains(state, *statePtr) {
		valid = false
	}
	if len(*justificationPtr) == 0 || !slices.Contains(justification, *justificationPtr) {
		valid = false
	}
	if len(*detailsPtr) <= 5 {
		valid = false
	}

	if !valid {
		fmt.Println("Usage:")
		fmt.Println("\tkey:\t", "any")
		b, _ := json.Marshal(state)
		fmt.Printf("\tstate:   \t%v\n", string(b))
		b, _ = json.Marshal(justification)
		fmt.Printf("\tjust:    \t%v\n", string(b))
		fmt.Println("\tdetails:\t", "> 5 characters long")
	}
	return valid
}

func unmarshal(file string) Vex {
	jsonFile, err := os.Open(file)

	if err != nil {
		fmt.Println(err)
	}

	byteValue, _ := io.ReadAll(jsonFile)

	var vex Vex
	err = json.Unmarshal(byteValue, &vex)
	if err != nil {
		fmt.Println(err)
	}

	return vex
}

func getBomRef(bom Vex, keyPtr *string) string {
	components := bom.Components
	bomRef := ""
	for _, component := range components {
		if strings.EqualFold(component.Name, *keyPtr) {
			bomRef = component.BomRef
		}
	}
	return bomRef
}

func setAnalysis(vex Vex, bomRef string, keyPtr *string, statePtr *string, justiPtr *string, detaiPtr *string) Vex {
	vulnerabilities := make([]Vulnerability, 0)

	if len(bomRef) > 0 {
		for idx, vul := range vex.Vulnerabilities {
			desc := vul.Description
			if strings.Contains(strings.ToLower(desc), strings.ToLower(*keyPtr)) {
				vex.Vulnerabilities[idx].Analysis.State = *statePtr
				vex.Vulnerabilities[idx].Analysis.Justification = *justiPtr
				vex.Vulnerabilities[idx].Analysis.Detail = *detaiPtr

				vulnerabilities = append(vulnerabilities, vex.Vulnerabilities[idx])
			}
		}
	}
	vex.Vulnerabilities = vulnerabilities
	fmt.Printf("count: %d\n", len(vex.Vulnerabilities))

	return vex
}

func write(vex Vex) {
	content, err := json.Marshal(vex)
	if err != nil {
		fmt.Println(err)
	}
	err = os.WriteFile("/home/fedora/Downloads/vex-updated.json", content, 0644)
	if err != nil {
		log.Fatal(err)
	}
}
