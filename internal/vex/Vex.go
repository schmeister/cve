package vex

import "time"

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
