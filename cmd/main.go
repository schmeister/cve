package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/fatih/color"

	"gheprivate.intra.corp/vss/cots-management/internal/analysis"
	"gheprivate.intra.corp/vss/cots-management/internal/components"
	"gheprivate.intra.corp/vss/cots-management/internal/constants"
	"gheprivate.intra.corp/vss/cots-management/internal/project"
	"gheprivate.intra.corp/vss/cots-management/internal/vulnerability"
	"gheprivate.intra.corp/vss/cots-management/validate"
)

// go run cmd/main.go -key="berkeley_db" -analysisState="NOT_AFFECTED" -analysisJustification="PROTECTED_AT_PERIMETER" -comment="my comment" -analysisDetails="Wednesday berkeley_db - 2" -suppressed=true

var URI = "http://10.125.140.97:8081"
var API_KEY = "odt_CnCius8VuTy6f7kxqEco7HAoIApQGxd2"
var PROJECT_ID = "daa3585b-1013-4dcf-b8c6-9d32b00077ec" // GSS - ACP OS
// var COMPONENT = "120c69dd-7157-4d09-a2ca-72cf78ae1d6e"     // bash
// var VULNERABILITY = "d93c63a4-7cea-4285-bbcc-767c0d7684fd" //CVE-2019-9924 (NVD)

func main() {
	sh := " (shorthand) "
	var flags = constants.Flags{}

	log.SetFlags(log.Lshortfile)

	flag.StringVar(&flags.Uri, "uri", URI, "URI of Dev-Track")
	flag.StringVar(&flags.Uri, "U", URI, "URI of Dev-Track"+sh)

	flag.StringVar(&flags.ApiKey, "apikey", API_KEY, "X-Api-Key")
	flag.StringVar(&flags.ApiKey, "AK", API_KEY, "X-Api-Key"+sh)

	flag.StringVar(&flags.Component, "component", "", "Component to be searched")
	flag.StringVar(&flags.Component, "CP", "", "Component to be searched"+sh)

	//flag.BoolVar(&flags.Suppressed, "suppressed", false, "Suppress the CVE")
	//flag.BoolVar(&flags.Suppressed, "S", false, "Suppress the CVE"+sh)

	flag.StringVar(&flags.State, "analysisState", "", "Analysis State: "+fmt.Sprint(constants.States))
	flag.StringVar(&flags.State, "AS", "", "Analysis State: "+sh+fmt.Sprint(constants.States))

	flag.StringVar(&flags.Justification, "analysisJustification", "", "Analysis Justification: "+fmt.Sprintln(constants.Justifications))
	flag.StringVar(&flags.Justification, "AJ", "", "Analysis Justification: "+sh+fmt.Sprintln(constants.Justifications))

	flag.StringVar(&flags.Project, "projectID", PROJECT_ID, "Project Details --> Object Identifier UUID")
	flag.StringVar(&flags.Project, "PID", PROJECT_ID, "Project Details --> Object Identifier UUID"+sh)

	flag.StringVar(&flags.Comment, "comment", "", "comments")
	flag.StringVar(&flags.Comment, "COM", "", "comments"+sh)

	flag.StringVar(&flags.Details, "analysisDetails", "", "Details")
	flag.StringVar(&flags.Details, "DET", "", "Details"+sh)

	flag.BoolVar(&flags.LP, "listP", false, "List projects")
	flag.BoolVar(&flags.LP, "LP", false, "List projects"+sh)

	flag.BoolVar(&flags.LC, "listC", false, "List components for project")
	flag.BoolVar(&flags.LC, "LC", false, "List components for project"+sh)

	flag.BoolVar(&flags.LV, "listV", false, "List vulnerabilities for project")
	flag.BoolVar(&flags.LV, "LV", false, "List vulnerabilities for project"+sh)

	flag.BoolVar(&flags.SIM, "simulate", false, "Simulate update only - If true only displays what will be updated")
	flag.BoolVar(&flags.SIM, "SIM", false, "Simulate update only - If true only displays what will be updated"+sh)

	flag.BoolVar(&flags.IS, "includesuppressed", false, "Include Supressed vulnerabilities - If false only non-suppressed vulnerabilities be included")
	flag.BoolVar(&flags.IS, "IS", false, "Include Supressed vulnerabilities - If false only non-suppressed vulnerabilities be included"+sh)

	flag.Parse()

	valid, vstr := validate.ValidateFlags(flags)

	if flags.LP { // List Projects
		projects := project.GetProjects(flags)
		projects.ListProjects()
	} else if flags.LC { // List Components
		components := components.GetComponents(flags)
		components.ListComponents()
	} else if flags.LV { // List Vulnerabilities
		v, res := validate.ValidateUUID(flags.Project)
		if !v {
			color.Set(color.FgYellow)
			log.Println(res)
			color.Unset()
		} else {
			vulnerabilities := vulnerability.GetVulnerabilities(flags, "project", flags.Project, 1)
			vulnerabilities.ListVulnerabilities()
			log.Println(len(vulnerabilities))
		}
	} else if !valid { // if not valid so far, print help.
		color.Set(color.FgYellow)
		log.Println(vstr)
		color.Unset()

		flag.PrintDefaults()
	} else {
		comps := components.GetComponents(flags)
		uuids := components.GetComponent(flags, comps)
		log.Printf("# Components: %d %s\n", len(uuids), uuids)
		for _, uuid := range uuids {
			page := 1
			vuls := vulnerability.GetAllVulnerabilities(flags, "component", uuid)
			for idx2, y := range vuls {
				if flags.State == "NOT_SET" || flags.State == "IN_TRIAGE" {
					flags.Suppressed = false
				} else {
					flags.Suppressed = true
				}

				an := analysis.PutAnalysis{
					Project:               flags.Project,
					Component:             uuid,
					Vulnerability:         y.UUID,
					AnalysisState:         flags.State,
					AnalysisJustification: flags.Justification,
					AnalysisResponse:      "CAN_NOT_FIX",
					Suppressed:            flags.Suppressed,
					IsSuppressed:          false,
					Comment:               flags.Comment,
					AnalysisDetails:       flags.Details,
				}
				if !flags.SIM {
					analysis.SaveAnalysis(flags, an)
				}
				num := ((page - 1) * 100) + idx2 + 1
				log.Printf("Vul: %4d %s %s %s %s \"%s\" \"%s\" \n", num, an.Project, an.Component, an.Vulnerability, an.AnalysisState, an.Comment, an.AnalysisDetails)
			}
			log.Println(len(vuls))
		}
	}
}
