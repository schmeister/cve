package project

import (
	"log"
	"testing"

	"github.com/schmeister/cve/internal/constants"
)

// go test -v ./...

func TestGetProjects(t *testing.T) {

	log.SetFlags(log.Lshortfile)

	flags := constants.Flags{
		Uri:           constants.URI,
		ApiKey:        constants.API_KEY,
		Component:     "",
		Suppressed:    false,
		State:         "",
		Justification: "",
		Project:       "",
		Comment:       "",
		Details:       "",
		LP:            false,
		LC:            false,
		LV:            false,
		SIM:           false,
		IS:            false,
	}

	projects := GetProjects(flags)
	t.Logf("%d\n", len(projects))

	pjs := projects.ListProjects()
	t.Logf("%v\n", pjs)

	project := projects.GetProject("tool")
	t.Logf("%v\n", project)
}
