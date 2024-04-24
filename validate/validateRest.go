package validate

import (
	"slices"

	"github.com/schmeister/cve/internal/constants"
)

func ValidateFlags(
	analysisStatePtr *string,
	analysisJustificationPtr *string,
	projectPtr *string,
	vulnerabilityPtr *string,
	componentPtr *string,
	analysisResponsePtr *string) bool {

	valid := true

	if len(*analysisStatePtr) > 0 && !slices.Contains(constants.States, *analysisStatePtr) {
		valid = false
	}

	if len(*analysisJustificationPtr) > 0 && !slices.Contains(constants.Justifications, *analysisJustificationPtr) {
		valid = false
	}
	if len(*projectPtr) != 36 && len(*componentPtr) != 36 && len(*vulnerabilityPtr) != 36 {
		valid = false
	}

	if len(*analysisResponsePtr) > 0 && !slices.Contains(constants.Vendors, *analysisResponsePtr) {
		valid = false
	}

	return valid
}