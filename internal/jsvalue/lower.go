package jsvalue

import (
	"sort"
	"strings"
	"unicode"
)

func inRanges(r rune, ranges [][2]rune) bool {
	i := sort.Search(len(ranges), func(i int) bool { return ranges[i][1] >= r })
	return i < len(ranges) && ranges[i][0] <= r
}

// JavaScript uses full default casing: dotted I expands and sigma is contextual.
func Lower(text string) string {
	runes := []rune(text)
	var result strings.Builder
	for i, r := range runes {
		if r == '\u0130' {
			result.WriteString("i\u0307")
			continue
		}
		if r == '\u03a3' {
			before, after := false, false
			for j := i - 1; j >= 0; j-- {
				if !inRanges(runes[j], caseIgnorableRanges) {
					before = inRanges(runes[j], casedRanges)
					break
				}
			}
			for j := i + 1; j < len(runes); j++ {
				if !inRanges(runes[j], caseIgnorableRanges) {
					after = inRanges(runes[j], casedRanges)
					break
				}
			}
			if before && !after {
				result.WriteRune('\u03c2')
				continue
			}
		}
		result.WriteRune(unicode.ToLower(r))
	}
	return result.String()
}
