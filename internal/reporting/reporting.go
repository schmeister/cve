package reporting

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sort"

	"github.com/schmeister/cve/internal/analysis"
	"github.com/schmeister/cve/internal/constants"
	"github.com/schmeister/cve/internal/finding"
	"github.com/schmeister/cve/internal/project"
)

type Analysis map[string]string

func Get(flags constants.Flags) Analysis {

	analysisMap := make(Analysis)

	findings := finding.GetFindings(flags)
	project := project.GetProject(flags)

	for _, y := range findings {
		cUUID := y.Component.UUID
		cName := y.Component.Name

		vUUID := y.Vulnerability.UUID
		vID := y.Vulnerability.VulnID

		if y.Analysis.State != nil {
			flags.Component = cUUID
			flags.Vulnerability = vUUID
			analysis := analysis.Get(flags)
			key := cName + "-" + vID

			an := fmt.Sprintf("%-5s, %-15s, %-15s, %-15s, %-15s, \"%s\"",
				project.Name, cName, vID,
				analysis.AnalysisState,
				analysis.AnalysisJustification,
				analysis.AnalysisDetails)

			analysisMap[key] = an
		}
	}
	return analysisMap
}

func (analysis Analysis) Print(){
	keys := make([]string, 0, len(analysis))
	for k := range analysis {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		log.Printf("[%s] %s", k, analysis[k])
	}
}

func (analysis Analysis) Save(flags constants.Flags){
	f, err := os.Create(flags.FILE)
	check(err)
	defer f.Close()
	
	w := bufio.NewWriter(f)
	keys := make([]string, 0, len(analysis))
	for k := range analysis {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		w.WriteString(fmt.Sprintf("%s, %s\n", k, analysis[k]))
	}
	w.Flush()
}

	
func check(e error) {
    if e != nil {
        panic(e)
    }
}