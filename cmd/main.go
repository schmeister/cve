package main

import (
	"flag"
	"log"

	"github.com/schmeister/cve/internal/analysis"
	"github.com/schmeister/cve/internal/components"
	"github.com/schmeister/cve/internal/vulnerability"
)

var URI = "http://localhost:8081"
var API_KEY = "odt_9SzIIWOMDrMm8IYwjVqZX8IBW90ppCCU"
var PROJECT_ID = "923e19be-0680-479a-9881-7a731df672c3"
var COMPONENT = "b2e85fce-fb7b-4c62-95c4-3e2d729993be" // zlib
var VULNERABILITY = "9a2fce2f-0b34-45fe-9ad4-6bea86aca3c9" //CVE-2023-6992 (NVD)

func main() {
	log.SetFlags(log.Lshortfile)

	uriPtr := flag.String("uri", URI, "URI")
	apiKeyPtr := flag.String("apikey", API_KEY, "X-Api-Key")
	keyPtr := flag.String("key", "", "Label to be searched")

	suppressedPtr := flag.Bool("suppressed", false, "Suppress the CVE")
	analysisStatePtr := flag.String("analysisState", "NOT_AFFECTED", "new analysis state")
	analysisJustificationPtr := flag.String("analysisJustification", "NOT_SET", "new analysis justification")
	projectPtr := flag.String("project", PROJECT_ID, "")
	commentPtr := flag.String("comment", "I have no comment.", "comments")
	analysisDetailsPtr := flag.String("analysisDetails", "There are no details.", "Details")

	flag.Parse()
	valid := true

	if valid {
		comps := components.GetComponents(*uriPtr, *apiKeyPtr, *projectPtr)
		uuids := components.GetComponent(*keyPtr, *apiKeyPtr, comps)
		log.Printf("# Components: %d\n", len(uuids))
		for _, uuid := range uuids {
			vuls := vulnerability.GetVulnerabilities(*uriPtr, *apiKeyPtr, uuid)
			log.Printf("# Vulnerabilities: %d\n", len(vuls))
			for _, y := range vuls {
				log.Printf("%-14s %s\n", y.VulnID, y.UUID)
				analyzed := analysis.PutAnalysis{
					Suppressed:            *suppressedPtr,
					AnalysisState:         *analysisStatePtr,
					AnalysisJustification: *analysisJustificationPtr,
					Project:               *projectPtr,
					Vulnerability:         y.UUID,
					Component:             uuid,
					IsSuppressed:          false,
					Comment:               *commentPtr,
					AnalysisDetails:       *analysisDetailsPtr,
				}
				analysis.SaveAnalysis(*uriPtr, *apiKeyPtr, analyzed)
			}
		}
	}
}