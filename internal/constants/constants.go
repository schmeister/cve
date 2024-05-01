package constants

var URI = "http://localhost:8081"
var API_KEY = "odt_9SzIIWOMDrMm8IYwjVqZX8IBW90ppCCU"
var PROJECT_ID = "882a7f3c-6791-4f84-9fba-d3aafa40c037" // GSS - ACP OS
var States = []string{"NOT_AFFECTED", "FALSE_POSITIVE", "NOT_SET", "RESOLVED", "IN_TRIAGE", "EXPLOITABLE"}
var Justifications = []string{"REQUIRES_ENVIRONMENT", "REQUIRES_CONFIGURATION", "NOT_SET", "REQUIRES_DEPENDENCY", "CODE_NOT_PRESENT", "PROTECTED_BY_MITIGATING_CONTROL", "CODE_NOT_REACHABLE", "PROTECTED_AT_PERIMETER", "PROTECTED_BY_COMPILER", "PROTECTED_AT_RUNTIME"}

type Flags struct {
	Uri           string
	ApiKey        string
	Component     string
	Suppressed    bool
	State         string
	Justification string
	Project       string
	Comment       string
	Details       string
	Vulnerability string
	LP            bool
	LC            bool
	LV            bool
	SIM           bool
	IS            bool
	REP           bool
}

//var Parameters = []string{"suppressed", "analysisState", "analysisJustification", "project", "vulnerability", "component", "isSuppressed", "comment", "analysisDetails", "analysisResponse"}
//var Vendors = []string{"ROLLBACK", "NOT_SET", "WORKAROUND_AVAILABLE", "UPDATE", "CAN_NOT_FIX", "WILL_NOT_FIX"}
//var StatesLC = []string{"not_affected", "false_positive", "not_set", "resolved", "in_triage", "exploitable"}
//var JustificationsLC = []string{"requires_environment", "requires_configuration", "not_set", "requires_dependency", "code_not_present", "protected_by_mitigating_control", "code_not_reachable", "protected_at_perimeter", "protected_by_compiler", "protected_at_runtine"}
