package updates

import (
	"regexp"
	"strconv"
	"strings"

	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
)

var versionPattern = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)$`)

func ParseVersion(text string) []float64 {
	m := versionPattern.FindStringSubmatch(js.Trim(text))
	if m == nil {
		return nil
	}
	result := make([]float64, 3)
	for i := range result {
		result[i], _ = strconv.ParseFloat(m[i+1], 64)
	}
	return result
}
func IsNewer(a, b string) bool {
	left, right := ParseVersion(a), ParseVersion(b)
	if left == nil || right == nil {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return left[i] > right[i]
		}
	}
	return false
}

type Offer struct {
	Version   string `json:"version"`
	Page      string `json:"page"`
	Installer string `json:"installer"`
}

func OfferFrom(release map[string]any, current, arch string) *Offer {
	if (arch != "x64" && arch != "arm64") || release == nil || js.Truth(release["draft"]) || js.Truth(release["prerelease"]) {
		return nil
	}
	version := strings.TrimPrefix(js.Text(release["tag_name"]), "v")
	if !IsNewer(version, current) {
		return nil
	}
	page := js.Text(release["html_url"])
	const base = "https://github.com/AyoubAchour/net-switch/releases/"
	if !strings.HasPrefix(page, base+"tag/") {
		return nil
	}
	name := "NetSwitch-Setup-" + version + "-" + arch + ".exe"
	assets, _ := release["assets"].([]any)
	for _, v := range assets {
		m := js.Object(v)
		if m["name"] != name {
			continue
		}
		installer := js.Text(m["browser_download_url"])
		if installer != base+"download/v"+version+"/"+name {
			return nil
		}
		return &Offer{version, page, installer}
	}
	return nil
}
