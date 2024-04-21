package validate

import (
	"slices"

	"github.com/schmeister/cve/internal/constants"
)

func ValidateRest(
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
	// Example:
	// my_project:    "923e19be-0680-479a-9881-7a731df672c3"
	// component(zlib):          "b2e85fce-fb7b-4c62-95c4-3e2d729993be"
	// CVE-2023-6992: "9a2fce2f-0b34-45fe-9ad4-6bea86aca3c9"
	if len(*projectPtr) != 36 && len(*componentPtr) != 36 && len(*vulnerabilityPtr) != 36 {
		valid = false
	}

	if len(*analysisResponsePtr) > 0 && !slices.Contains(constants.Vendors, *analysisResponsePtr) {
		valid = false
	}

	return valid
}