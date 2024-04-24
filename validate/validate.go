package validate

import (
	"slices"

	"github.com/schmeister/cve/internal/constants"
)

func ValidateFlags(	analysisStatePtr *string, analysisJustificationPtr *string) bool {

	valid := true

	if len(*analysisStatePtr) > 0 && !slices.Contains(constants.States, *analysisStatePtr) {
		valid = false
	}

	if len(*analysisJustificationPtr) > 0 && !slices.Contains(constants.Justifications, *analysisJustificationPtr) {
		valid = false
	}

	return valid
}
