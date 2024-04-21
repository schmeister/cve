package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/schmeister/cve/internal/analysis"
	"github.com/schmeister/cve/internal/components"
	"github.com/schmeister/cve/internal/constants"
	"github.com/schmeister/cve/internal/vex"
	"github.com/schmeister/cve/internal/vulnerability"
	"github.com/schmeister/cve/validate"
)

// BOM: http://localhost:8081/api/v1/bom/cyclonedx/project/923e19be-0680-479a-9881-7a731df672c3?download=false
// Parse: scan components for ZLIB (or other component) just like the VEX way.

func main() {
	keyPtr := flag.String("key", "", "Label to be searched")

	statePtr := flag.String("state", "", "new state")
	justificationPtr := flag.String("just", "", "justification")
	detailsPtr := flag.String("details", "", "details")
	//suppressedPtr := flag.Bool("suppressed", false, "Suppress the CVE")
	analysisStatePtr := flag.String("analysisState", "", "new analysis state")
	analysisJustificationPtr := flag.String("analysisJustification", "", "new analysis justification")
	projectPtr := flag.String("project", constants.Project, "")
	componentPtr := flag.String("component", constants.Component, "")
	vulnerabilityPtr := flag.String("vulnerability", constants.Vulnerability, "")
	//isSuppressedPtr := flag.Bool("isSuppressed", false, "Suppress the CVE")
	//commentPtr := flag.String("comment", "", "comments")
	//analysisDetailsPtr := flag.String("analysisDetails", "", "")
	analysisResponsePtr := flag.String("analysisResponse", "", "")
	flag.Parse()

	valid := validate.ValidateVex(keyPtr, statePtr, justificationPtr, detailsPtr)
	validate.ValidateRest(analysisStatePtr, analysisJustificationPtr, projectPtr, vulnerabilityPtr, componentPtr, analysisResponsePtr)

	if valid {
		vexFile := unmarshal("/home/fedora/Downloads/vex.json")
		bomFile := unmarshal("/home/fedora/Downloads/bom.json")

		bomRef := getBomRef(bomFile, keyPtr)
		fmt.Printf("%s(\x1b[%dm%s\x1b[0m)\n", bomRef, 34, *keyPtr)

		vexFile = setAnalysis(vexFile, bomRef, keyPtr, statePtr, justificationPtr, detailsPtr)
		write(vexFile)

		//theBom := rest.GetBOM("923e19be-0680-479a-9881-7a731df672c3")
		//comps := bom.GetComponents(theBom, keyPtr)
		//fmt.Println(comps)

		comps := components.GetComponents("923e19be-0680-479a-9881-7a731df672c3")
		for _, y := range comps {
			if strings.EqualFold(y.Name, *keyPtr) {
				fmt.Printf("%-14s %s\n", y.Name, y.UUID)
			}
		}
		uuid := components.GetComponent(*keyPtr, comps)
		for _, y := range uuid {
			vuls := vulnerability.GetVulnerabilities(y)
			vulnerability.ShowVulnerabilities(vuls)
		}

	}
}

func unmarshal(file string) vex.Vex {
	jsonFile, err := os.Open(file)

	if err != nil {
		fmt.Println(err)
	}

	byteValue, _ := io.ReadAll(jsonFile)

	var vex vex.Vex
	err = json.Unmarshal(byteValue, &vex)
	if err != nil {
		fmt.Println(err)
	}

	return vex
}

func getBomRef(bom vex.Vex, keyPtr *string) string {
	components := bom.Components
	bomRef := ""
	for _, component := range components {
		if strings.EqualFold(component.Name, *keyPtr) {
			bomRef = component.BomRef
		}
	}
	return bomRef
}

func setAnalysis(v vex.Vex, bomRef string, keyPtr *string, statePtr *string, justiPtr *string, detaiPtr *string) vex.Vex {
	vulnerabilities := make([]vex.Vulnerability, 0)

	if len(bomRef) > 0 {
		for idx, vul := range v.Vulnerabilities {
			desc := vul.Description
			if strings.Contains(strings.ToLower(desc), strings.ToLower(*keyPtr)) {
				if len(*statePtr) > 0 {
					v.Vulnerabilities[idx].Analysis.State = *statePtr
				}
				if len(*justiPtr) > 0 {
					v.Vulnerabilities[idx].Analysis.Justification = *justiPtr
				}

				v.Vulnerabilities[idx].Analysis.Detail = *detaiPtr

				vulnerabilities = append(vulnerabilities, v.Vulnerabilities[idx])
			}
		}
	}
	v.Vulnerabilities = vulnerabilities
	fmt.Printf("count: %d\n", len(v.Vulnerabilities))

	return v
}

func write(vex vex.Vex) {
	content, err := json.Marshal(vex)
	if err != nil {
		fmt.Println(err)
	}
	err = os.WriteFile("/home/fedora/Downloads/vex-updated.json", content, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func testPUT() {
	host := "http://localhost:8081/api/v1"
	route := "analysis"
	url := fmt.Sprintf("%s/%s", host, route)

	// zlib
	data := []byte(`
	{
		"suppressed": false,
		"analysisState":"NOT_AFFECTED",
		"analysisJustification":"REQUIRES_CONFIGURATION",
		"project":"923e19be-0680-479a-9881-7a731df672c3", 
		"vulnerability": "9a2fce2f-0b34-45fe-9ad4-6bea86aca3c9", 
		"component":"b2e85fce-fb7b-4c62-95c4-3e2d729993be", 
		"isSuppressed":false, 
		"comment":"another comment - just for testing - really late - omg",
		"analysisDetails":"analysisDetails refactored - really late - omg",
		"analysisResponse": "WORKAROUND_AVAILABLE"
	}`)

	req, err := http.NewRequest(
		http.MethodPut,
		// "http://localhost:8081/api/v1/component/b2e85fce-fb7b-4c62-95c4-3e2d729993be",
		// "http://localhost:8081/api/version",
		// "http://localhost:8081/api/v1/vulnerability",
		url,
		bytes.NewBuffer(data),
	)
	if err != nil {
		log.Fatalf("error creating HTTP request: %v", err)
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("X-Api-Key", "odt_9SzIIWOMDrMm8IYwjVqZX8IBW90ppCCU")
	req.Header.Add("content-type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("error sending HTTP request: %v", err)
	}

	responseBytes, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("error reading HTTP response body: %v", err)
	}

	newG := analysis.GetAnalysis{}
	json.Unmarshal(responseBytes, &newG)

	j, _ := json.MarshalIndent(newG, "", " ")
	fmt.Printf("%v\n", string(responseBytes))
	fmt.Printf("%v\n", string(j))
}

func testGET() {
	host := "http://localhost:8081/api/v1"
	route := "analysis"
	url := fmt.Sprintf("%s/%s?project=%s&component=%s&vulnerability=%s", host, route, constants.Project, constants.Component, constants.Vulnerability)

	req, err := http.NewRequest(
		http.MethodGet,
		// "http://localhost:8081/api/v1/component/b2e85fce-fb7b-4c62-95c4-3e2d729993be",
		// "http://localhost:8081/api/version",
		// "http://localhost:8081/api/v1/vulnerability",
		url,
		nil,
	)
	if err != nil {
		log.Fatalf("error creating HTTP request: %v", err)
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("X-Api-Key", "odt_9SzIIWOMDrMm8IYwjVqZX8IBW90ppCCU")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("error sending HTTP request: %v", err)
	}

	responseBytes, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("error reading HTTP response body: %v", err)
	}

	newG := analysis.GetAnalysis{}
	json.Unmarshal(responseBytes, &newG)

	j, _ := json.MarshalIndent(newG, "", " ")
	fmt.Printf("%v\n", string(responseBytes))
	fmt.Printf("%v\n", string(j))
}
