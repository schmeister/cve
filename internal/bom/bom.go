package bom

import (
	"fmt"
	"strings"
	"time"
)

type BOM struct {
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
		Name               string `json:"name"`
		ExternalReferences []struct {
			Type    string `json:"type"`
			URL     string `json:"url"`
			Comment string `json:"comment"`
		} `json:"externalReferences,omitempty"`
		Type     string `json:"type"`
		BomRef   string `json:"bom-ref"`
		Supplier struct {
			Name string `json:"name"`
		} `json:"supplier,omitempty"`
		Version string `json:"version,omitempty"`
		Cpe     string `json:"cpe,omitempty"`
	} `json:"components"`
	Dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	} `json:"dependencies"`
}

func GetComponents(bom BOM, keyPtr *string) []string {

	components := bom.Components
	s := make([]string, 3)
	for _, component := range components {
		if strings.EqualFold(component.Name, *keyPtr) {
			fmt.Println(component.Name,component.BomRef)
			s = append(s, component.BomRef)
		}
	}
	return s
}
