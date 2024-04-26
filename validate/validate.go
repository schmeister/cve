package validate

import (
	"regexp"
	"slices"

	"github.com/schmeister/cve/internal/constants"
)

func ValidateFlags(flags constants.Flags) (bool, string) {
	if len(flags.Component) == 0 {
		return false, "Invalid component"
	}

	if len(flags.State) == 0 || (len(flags.State) > 0 && !slices.Contains(constants.States, flags.State)) {
		return false, "Invalid State"
	}

	if len(flags.Justification) > 0 && !slices.Contains(constants.Justifications, flags.Justification) {
		return false, "Invalid Justification"
	}

	if len(flags.Details) < 10 && len(flags.Comment) < 10 {
		return false, "Invalid Details or Comments - either or both must have text of 10 characters longer"
	}

	return true, ""
}

func ValidateUUID(uuid string) (bool, string) {

	uuidpattern := "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
	res1, e := regexp.MatchString(uuidpattern, uuid)
	if !res1 || e != nil {
		response := "Invalid Project UUID. Must match: " + uuidpattern
		return false, response
	}
	return true, ""
}
