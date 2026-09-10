package vswitch

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func serversResources() map[string]*schema.Resource {
	return map[string]*schema.Resource{
		ResourceType:        Resource(),
		ServersResourceType: ServersResource(),
	}
}

// serversDiff plans config against stored and reports the servers attributes that changed.
func serversDiff(t *testing.T, res *schema.Resource, stored, config []any) []string {
	t.Helper()

	data := schema.TestResourceDataRaw(t, res.Schema, map[string]any{"servers": stored})
	data.SetId("70996")

	diff, err := res.Diff(
		context.Background(),
		data.State(),
		terraform.NewResourceConfigRaw(map[string]any{"servers": config}),
		nil,
	)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	var changes []string

	if diff != nil {
		for attr, d := range diff.Attributes {
			if strings.HasPrefix(attr, "servers") {
				changes = append(changes, fmt.Sprintf("%s %v", attr, d))
			}
		}
	}

	// Sort because diff.Attributes iterates in random order.
	sort.Strings(changes)

	return changes
}

func TestServersOrderIsNotAChange(t *testing.T) {
	t.Parallel()

	stored := []any{2614609, 2628146, 2632954, 3002292}
	reordered := []any{2614609, 3002292, 2628146, 2632954}

	for name, res := range serversResources() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			changes := serversDiff(t, res, stored, reordered)
			if len(changes) > 0 {
				t.Errorf("reordered servers planned as a change: %v", changes)
			}
		})
	}
}

func TestServersAddIsAChange(t *testing.T) {
	t.Parallel()

	stored := []any{2614609, 2628146, 2632954, 3002292}
	added := append(slices.Clone(stored), 3100000)

	for name, res := range serversResources() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			changes := serversDiff(t, res, stored, added)
			if len(changes) == 0 {
				t.Error("added server did not plan as a change")
			}
		})
	}
}

func TestParseServerIDs(t *testing.T) {
	t.Parallel()

	set := schema.NewSet(
		schema.HashSchema(&schema.Schema{Type: schema.TypeInt}),
		[]any{3, 1, 2},
	)

	got := parseServerIDs(set)
	sort.Ints(got)

	want := []int{1, 2, 3}
	if !slices.Equal(got, want) {
		t.Errorf("parseServerIDs = %v, want %v", got, want)
	}
}

func TestDiffServers(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name         string
		oldList      []int
		newList      []int
		wantToAdd    []int
		wantToRemove []int
	}

	testCases := []testCase{
		{
			name:         "No Changes",
			oldList:      []int{1, 2, 3},
			newList:      []int{1, 2, 3},
			wantToAdd:    []int{},
			wantToRemove: []int{},
		},
		{
			name:         "No Changes from unordered",
			oldList:      []int{1, 2, 3},
			newList:      []int{3, 2, 1},
			wantToAdd:    []int{},
			wantToRemove: []int{},
		},
		{
			name:         "Add Servers",
			oldList:      []int{1, 2},
			newList:      []int{1, 2, 3, 4},
			wantToAdd:    []int{3, 4},
			wantToRemove: []int{},
		},
		{
			name:         "Remove Servers",
			oldList:      []int{1, 2, 3, 4},
			newList:      []int{1, 2},
			wantToAdd:    []int{},
			wantToRemove: []int{3, 4},
		},
		{
			name:         "Mixed Add and Remove",
			oldList:      []int{1, 2, 3},
			newList:      []int{2, 3, 4},
			wantToAdd:    []int{4},
			wantToRemove: []int{1},
		},
		{
			name:         "Empty Old List",
			oldList:      []int{},
			newList:      []int{1, 2},
			wantToAdd:    []int{1, 2},
			wantToRemove: []int{},
		},
		{
			name:         "Empty New List",
			oldList:      []int{1, 2},
			newList:      []int{},
			wantToAdd:    []int{},
			wantToRemove: []int{1, 2},
		},
	}

	compareOutput := func(actual, want []int) bool {
		sort.Ints(actual)
		sort.Ints(want)

		return slices.Equal(actual, want)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			toAdd, toRemove := diffServers(tc.oldList, tc.newList)
			if !compareOutput(toAdd, tc.wantToAdd) {
				t.Errorf("Test %s: toAdd = %v, want %v", tc.name, toAdd, tc.wantToAdd)
			}

			if !compareOutput(toRemove, tc.wantToRemove) {
				t.Errorf("Test %s: toRemove = %v, want %v", tc.name, toRemove, tc.wantToRemove)
			}
		})
	}
}
