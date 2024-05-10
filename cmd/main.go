package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/fatih/color"
	"github.com/schmeister/cve/internal/analysis"
	"github.com/schmeister/cve/internal/components"
	"github.com/schmeister/cve/internal/constants"
	"github.com/schmeister/cve/internal/project"
	"github.com/schmeister/cve/internal/reporting"
	"github.com/schmeister/cve/internal/vulnerability"
	"github.com/schmeister/cve/validate"
)

// go run cmd/main.go -key="berkeley_db" -analysisState="NOT_AFFECTED" -analysisJustification="PROTECTED_AT_PERIMETER" -comment="my comment" -analysisDetails="Wednesday berkeley_db - 2" -suppressed=true

var URI = "http://localhost:8081"
var API_KEY = "odt_9SzIIWOMDrMm8IYwjVqZX8IBW90ppCCU"
var PROJECT_ID = "882a7f3c-6791-4f84-9fba-d3aafa40c037" // GSS - ACP OS
// var COMPONENT = "120c69dd-7157-4d09-a2ca-72cf78ae1d6e"     // bash
// var VULNERABILITY = "d93c63a4-7cea-4285-bbcc-767c0d7684fd" //CVE-2019-9924 (NVD)

func main() {
	var flags = constants.Flags{}

	log.SetFlags(log.Lshortfile)
	//log.SetFlags(log.Lmsgprefix)

	flag.StringVar(&flags.Uri, "U", URI, "URI of Dev-Track")
	flag.StringVar(&flags.ApiKey, "AK", API_KEY, "X-Api-Key")
	flag.StringVar(&flags.Component, "CP", "", "Component to be searched")
	flag.StringVar(&flags.State, "AS", "", "Analysis State: "+fmt.Sprint(constants.States))
	flag.StringVar(&flags.Justification, "AJ", "", "Analysis Justification: "+fmt.Sprintln(constants.Justifications))
	flag.StringVar(&flags.Project, "PID", PROJECT_ID, "Project Details --> Object Identifier UUID")
	flag.StringVar(&flags.Comment, "COM", "", "comments")
	flag.StringVar(&flags.Details, "DET", "", "Details")
	flag.BoolVar(&flags.Help, "H", false, "Help")
	flag.BoolVar(&flags.LP, "LP", false, "List projects")
	flag.BoolVar(&flags.LC, "LC", false, "List components for project")
	flag.BoolVar(&flags.LV, "LV", false, "List vulnerabilities for project")
	flag.BoolVar(&flags.SIM, "SIM", false, "Simulate update only - If true only displays what will be updated")
	flag.BoolVar(&flags.IS, "IS", false, "Include Supressed vulnerabilities - If false only non-suppressed vulnerabilities be included")
	flag.BoolVar(&flags.REP, "REP", false, "Create report for Project")
	flag.StringVar(&flags.OUT, "OUT", "", "Output filename to save report to")
	flag.StringVar(&flags.Vulnerability, "VUL", "", "Vulnerability name")
	flag.Parse()

	valid, vstr := validate.ValidateFlags(flags)

	if flags.Help {
		help.Help(flags)

	} else if flags.LP { // List Projects
		projs := project.GetProjects(flags)
		projs.ListProjects(flags)
	} else if flags.LC { // List Components
		if validate.IsValidUUID(flags.Project) {
			components, cMap := components.GetProjectComponents(flags)
			components.ListComponents(flags)
			cMap.ListComponents(flags)
		} else {
			log.Printf("%s", help.Red("Invalid Project UUID format"))
			return
		}
	} else if flags.LV { // List Vulnerabilities
		if validate.IsValidUUID(flags.Project) {
			_, acMap := components.GetProjectComponents(flags)
			namedComps := acMap.GetComponentsFromName(flags)
			cKeys := namedComps.Sort()

			numVuls := 0

			for _, key := range cKeys {
				aComp := namedComps[key]

				_, vuls := vulnerability.GetAllVulnerabilities(flags, "component", aComp.UUID)
				vKeys := vuls.Sort()

				for _, vKey := range vKeys {
					vul := vuls[vKey]
					wrapped2 := help.WordWrap(vul.Description, 80, 10)
					fmt.Printf("%-25s %20s %s\n", help.Yellow(vul.VulnID), help.Magenta(aComp.Name+"-"+aComp.Version), help.Cyan(vul.Cwe.Name))
					fmt.Printf("%s\n\n", help.White(wrapped2))
				}
				numVuls += len(vKeys)
			}
			log.Printf("Components     : %d", len(cKeys))
			log.Printf("Vulnerabilities: %d", numVuls)
		} else {
			log.Printf("%s", help.Red("Invalid Project UUID format"))
			return
		}
	} else if flags.REP { // Generate Report
		an := reporting.Get(flags)
		if len(flags.OUT) > 0 {
			an.Save(flags)
		} else {
			an.Print()
		}
	} else if !valid { // if not valid so far, print help.
		log.Printf("%s", help.Red(vstr))

		flag.PrintDefaults()
	} else {
		allComps, _ := components.GetProjectComponents(flags)
		namedComps := allComps.GetComponentsFromName(flags)
		proj := project.GetProject(flags)
		log.Printf("# Components: %d\n", len(namedComps))
		count := 1
		for _, aComp := range namedComps {
			_, vuls := vulnerability.GetAllVulnerabilities(flags, "component", aComp.UUID)
			keys := vuls.Sort()
			for _, key := range keys {
				vul := vuls[key]
				if flags.State == "NOT_SET" || flags.State == "IN_TRIAGE" {
					flags.Suppressed = false
				} else {
					flags.Suppressed = true
				}
				an := analysis.PutAnalysis{
					Project:               flags.Project,
					Component:             aComp.UUID,
					Vulnerability:         vul.UUID,
					AnalysisState:         flags.State,
					AnalysisJustification: flags.Justification,
					AnalysisResponse:      "CAN_NOT_FIX",
					Suppressed:            flags.Suppressed,
					IsSuppressed:          false,
					Comment:               flags.Comment,
					AnalysisDetails:       flags.Details,
				}
				if !flags.SIM {
					an.Save(flags)
				}
				log.Printf("%4d [%s] [%s-%s] [%-14s] %s %s \"%s\" \n", count, proj.Name, aComp.Name, aComp.Version, vul.VulnID, an.AnalysisState, an.AnalysisJustification, an.AnalysisDetails)
				count++
			}
		}
		project.Refresh(flags)
	}
}
