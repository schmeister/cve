package constants

var Parameters = []string{"suppressed", "analysisState", "analysisJustification", "project", "vulnerability", "component", "isSuppressed", "comment", "analysisDetails", "analysisResponse"}
var States = []string{"NOT_AFFECTED", "FALSE_POSITIVE", "NOT_SET", "RESOLVED", "IN_TRIAGE", "EXPLOITABLE"}
var Justifications = []string{"REQUIRES_ENVIRONMENT", "REQUIRES_CONFIGURATION", "NOT_SET", "REQUIRES_DEPENDENCY", "CODE_NOT_PRESENT", "PROTECTED_BY_MITIGATING_CONTROL", "CODE_NOT_REACHABLE", "PROTECTED_AT_PERIMETER", "PROTECTED_BY_COMPILER", "PROTECTED_AT_RUNTIME"}
var Vendors = []string{"ROLLBACK", "NOT_SET", "WORKAROUND_AVAILABLE", "UPDATE", "CAN_NOT_FIX", "WILL_NOT_FIX"}

var StatesLC = []string{"not_affected", "false_positive", "not_set", "resolved", "in_triage", "exploitable"}
var JustificationsLC = []string{"requires_environment", "requires_configuration", "not_set", "requires_dependency", "code_not_present", "protected_by_mitigating_control", "code_not_reachable", "protected_at_perimeter", "protected_by_compiler", "protected_at_runtine"}

var Project = "923e19be-0680-479a-9881-7a731df672c3"
var Component = "b2e85fce-fb7b-4c62-95c4-3e2d729993be"
var Vulnerability = "9a2fce2f-0b34-45fe-9ad4-6bea86aca3c9"
