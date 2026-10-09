package handler

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// The NotificationEvent.key enum in swagger.yaml is what generated clients
// validate channel subscriptions against. It drifted once already (ip.detected
// was never listed), so it is pinned to the catalogue the server enforces.
func TestSwaggerNotificationEventEnumMatchesCatalogue(t *testing.T) {
	spec := string(swaggerYAML)
	start := strings.Index(spec, "\n    NotificationEvent:\n")
	if start < 0 {
		t.Fatal("NotificationEvent schema not found in swagger.yaml")
	}
	block := spec[start+1:]
	if end := regexp.MustCompile(`\n    [A-Za-z]`).FindStringIndex(block[1:]); end != nil {
		block = block[:end[0]+1]
	}
	enum := strings.Index(block, "enum:\n")
	if enum < 0 {
		t.Fatal("NotificationEvent.key has no enum")
	}
	var documented []string
	for _, line := range strings.Split(block[enum+len("enum:\n"):], "\n") {
		item, ok := strings.CutPrefix(strings.TrimSpace(line), "- ")
		if !ok {
			break
		}
		documented = append(documented, item)
	}
	var catalogue []string
	for _, e := range model.EventCatalogue {
		catalogue = append(catalogue, e.Key)
	}
	sort.Strings(documented)
	sort.Strings(catalogue)
	if strings.Join(documented, ",") != strings.Join(catalogue, ",") {
		t.Fatalf("swagger NotificationEvent.key enum\n  %v\ndiffers from model.EventCatalogue\n  %v", documented, catalogue)
	}
}
