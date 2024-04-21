package analysis

type GetAnalysis struct {
	AnalysisState         string `json:"analysisState"`
	AnalysisJustification string `json:"analysisJustification"`
	AnalysisDetails       string `json:"analysisDetails"`
	AnalysisComments      []struct {
		Timestamp int64  `json:"timestamp"`
		Comment   string `json:"comment"`
		Commenter string `json:"commenter"`
	} `json:"analysisComments"`
	IsSuppressed bool `json:"isSuppressed"`
}

type PutAnalysis struct {
	Suppressed            bool   `json:"suppressed,omitempty"`
	AnalysisState         string `json:"analysisState,omitempty"`
	AnalysisJustification string `json:"analysisJustification,omitempty"`
	Project               string `json:"project"`
	Vulnerability         string `json:"vulnerability"`
	Component             string `json:"component"`
	IsSuppressed          bool   `json:"isSuppressed,omitempty"`
	Comment               string `json:"comment,omitempty"`
	AnalysisDetails       string `json:"analysisDetails,omitempty"`
	AnalysisResponse      string `json:"analysisResponse,omitempty"`
}
