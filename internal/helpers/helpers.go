package helpers

import (
	"fmt"
	"log"
	"strings"

	"github.com/fatih/color"
)

func WordWrap(text string, lineWidth int, indent int) string {
	pad := fmt.Sprintf("%*s", indent, " ")
	words := strings.Fields(strings.TrimSpace(text))
	if len(words) == 0 {
		return pad + text
	}
	wrapped := pad + words[0]
	spaceLeft := lineWidth - len(wrapped)
	for _, word := range words[1:] {
		if len(word)+1 > spaceLeft {
			wrapped += "\n" + pad + word
			spaceLeft = lineWidth - len(word)
		} else {
			wrapped += " " + word
			spaceLeft -= 1 + len(word)
		}
	}

	return wrapped
}

var Yellow = color.New(color.FgYellow).SprintFunc()
var Cyan = color.New(color.FgHiCyan).SprintFunc()
var White = color.New(color.FgHiWhite).SprintFunc()
var Blue = color.New(color.FgHiBlue).SprintFunc()
var Magenta = color.New(color.FgHiMagenta).SprintFunc()
var Red = color.New(color.FgHiRed).SprintFunc()

func Colorize(desc, call string) {
	log.Printf("\n%s\n\t%s", Blue(desc), Yellow(call))
}

type helpers []helper
type helper struct {
	desc string
	cmd  string
}

func (helps helpers) print() {
	for _, y := range helps {
		fmt.Printf("%s\n\t%s\n", Blue(y.desc), Yellow(y.cmd))
	}
}

func Help(flags constants.Flags) {
	var lv helpers
	if flags.Help && flags.LP {
		lv = helpLP()
	} else if flags.Help && flags.LV {
		lv = helpLV()
	}
	lv.print()
}

func helpLP() helpers {
	lv := helpers{{
		desc: `List Projects (-LP)`,
		cmd:  `main -LP`,
	}}
	return lv
}

func helpLV() helpers {
	lv := helpers{{
		desc: `List Vulnerabilities (-LV) for project (-PID) *77ec, and component (-CP) "openssh"`,
		cmd:  `main -PID "daa3585b-1013-4dcf-b8c6-9d32b00077ec" -LV -CP "openssh"`,
	}, {
		desc: `List Vulnerabilities (-LV) for project (-PID) *77ec, and ALL components (-CP)`,
		cmd:  `main -PID "daa3585b-1013-4dcf-b8c6-9d32b00077ec" -LV -CP ""`,
	}, {
		desc: `List Vulnerabilities (-LV) for project (-PID) *77ec, and ALL components (-CP), Include Suppressed (-IS) vulnerabilities`,
		cmd:  `main -PID "daa3585b-1013-4dcf-b8c6-9d32b00077ec" -LV -CP "" -IS`,
	}}
	return lv
}
