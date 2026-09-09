package vswitch

import (
	"context"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// TestServersOrderIsNotAChange asserts that a configuration listing the servers
// in an order other than the ascending one Read stores does not plan as a change.
func TestServersOrderIsNotAChange(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		resource *schema.Resource
		stored   map[string]any
		config   map[string]any
	}

	stored := []any{2614609, 2628146, 2632954, 3002292}
	configured := []any{2614609, 3002292, 2628146, 2632954}

	testCases := []testCase{
		{
			name:     ResourceType,
			resource: Resource(),
			stored:   map[string]any{"name": "main", "vlan": 4001, "servers": stored},
			config:   map[string]any{"name": "main", "vlan": 4001, "servers": configured},
		},
		{
			name:     ServersResourceType,
			resource: ServersResource(),
			stored:   map[string]any{"vswitch_id": "70996", "servers": stored},
			config:   map[string]any{"vswitch_id": "70996", "servers": configured},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			data := schema.TestResourceDataRaw(t, tc.resource.Schema, tc.stored)
			data.SetId("70996")

			diff, err := tc.resource.Diff(
				context.Background(),
				data.State(),
				terraform.NewResourceConfigRaw(tc.config),
				nil,
			)
			if err != nil {
				t.Fatalf("Diff: %v", err)
			}

			if diff == nil {
				return
			}

			for attr, d := range diff.Attributes {
				if strings.HasPrefix(attr, "servers") {
					t.Errorf("reordered servers planned as a change: %s %v", attr, d)
				}
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
