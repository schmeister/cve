package validate

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/schmeister/cve/internal/constants"
)

func ValidateVex(keyPtr, statePtr, justificationPtr, detailsPtr *string) bool {
	valid := true
	if len(*keyPtr) < 3 {
		valid = false
	}
	if len(*statePtr) > 0 && !slices.Contains(constants.StatesLC, *statePtr) {
		valid = false
	}
	if len(*justificationPtr) > 0 && !slices.Contains(constants.JustificationsLC, *justificationPtr) {
		valid = false
	}
	if len(*detailsPtr) <= 5 {
		valid = false
	}

	if !valid {
		fmt.Println("Usage:")
		fmt.Println("\tkey:\t", "any")
		b, _ := json.Marshal(constants.StatesLC)
		fmt.Printf("\tstate:   \t%v\n", string(b))
		b, _ = json.Marshal(constants.JustificationsLC)
		fmt.Printf("\tjust:    \t%v\n", string(b))
		fmt.Println("\tdetails:\t", "> 5 characters long")
	}
	return valid
}
