package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/schmeister/cve/internal/analysis"
	"github.com/schmeister/cve/internal/components"
	"github.com/schmeister/cve/internal/constants"
	"github.com/schmeister/cve/internal/vulnerability"
	"github.com/schmeister/cve/validate"
)

// go run cmd/main.go -key="berkeley_db" -analysisState="NOT_AFFECTED" -analysisJustification="PROTECTED_AT_PERIMETER" -comment="my comment" -analysisDetails="Wednesday berkeley_db - 2" -suppressed=true

var URI = "http://localhost:8081"
var API_KEY = "odt_9SzIIWOMDrMm8IYwjVqZX8IBW90ppCCU"
var PROJECT_ID = "882a7f3c-6791-4f84-9fba-d3aafa40c037"
var COMPONENT = "d37ef235-dc99-4a3b-9937-e9e4a6615e9f"     // berkley_db
var VULNERABILITY = "d3ad8c72-1f98-4614-b1c4-745da7a88bc7" //CVE-2019-2708 (NVD)

func main() {
	log.SetFlags(log.Lshortfile)

	uriPtr := flag.String("uri", URI, "URI")
	apiKeyPtr := flag.String("apikey", API_KEY, "X-Api-Key")
	keyPtr := flag.String("key", "firefox", "Label to be searched")

	suppressedPtr := flag.Bool("suppressed", false, "Suppress the CVE")
	analysisStatePtr := flag.String("analysisState", "NOT_AFFECTED", fmt.Sprintln(constants.States))
	analysisJustificationPtr := flag.String("analysisJustification", "NOT_SET", fmt.Sprintln(constants.Justifications))
	projectPtr := flag.String("project", PROJECT_ID, "")
	commentPtr := flag.String("comment", "no comment", "comments")
	analysisDetailsPtr := flag.String("analysisDetails", "no details", "Details")

	flag.Parse()

	valid := validate.ValidateFlags(analysisStatePtr, analysisJustificationPtr)
	if !valid {
		flag.PrintDefaults()
	} else {
		comps := components.GetComponents(*uriPtr, *apiKeyPtr, *projectPtr)
		uuids := components.GetComponent(*keyPtr, *apiKeyPtr, comps)
		log.Printf("# Components: %d %s\n", len(uuids), uuids)
		for _, uuid := range uuids {
			page := 1
			vuls := vulnerability.GetVulnerabilities(*uriPtr, *apiKeyPtr, uuid, page)
			for len(vuls) > 0 {
				log.Printf("# Vulnerabilities: %d\n", len(vuls))
				for idx, y := range vuls {
					log.Printf("%3d %-14s %s\n", idx+1, y.VulnID, y.UUID)
					if true {
						an := analysis.PutAnalysis{
							Project:               *projectPtr,
							Component:             uuid,
							Vulnerability:         y.UUID,
							AnalysisState:         *analysisStatePtr,
							AnalysisJustification: *analysisJustificationPtr,
							AnalysisResponse:      "CAN_NOT_FIX",
							Suppressed:            *suppressedPtr,
							IsSuppressed:          false,
							Comment:               *commentPtr,
							AnalysisDetails:       *analysisDetailsPtr,
						}
						analysis.SaveAnalysis(*uriPtr, *apiKeyPtr, an)
					}
				}

				page++
				vuls = vulnerability.GetVulnerabilities(*uriPtr, *apiKeyPtr, uuid, page)
			}
		}
	}
}
