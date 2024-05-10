package validate

import (
	"slices"
	"github.com/google/uuid"

	"gheprivate.intra.corp/vss/cots-management/internal/constants"
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

	if len(flags.Details) < 10 && len(flags.Comment)<10 {
		return false, "Invalid Details or Comments - either or both must have text of 10 characters longer"
	}

	return true, ""
}

func IsValidUUID(u string) bool {
    _, err := uuid.Parse(u)
    return err == nil
 }
