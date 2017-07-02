package main

import (
	"reflect"
	"testing"
)

func TestFilterRoles(t *testing.T) {
	tests := []struct {
		roles  []string
		filter string
		want   []string
	}{{
		// special case
		roles:  []string{},
		filter: ".",
		want:   []string{},
	}, {
		// "" matches everthing
		roles:  []string{"alpha", "beta", "gamma"},
		filter: "",
		want:   []string{"alpha", "beta", "gamma"},
	}, {
		// "delta" matches nothing
		roles:  []string{"alpha", "beta", "gamma"},
		filter: "delta",
		want:   []string{},
	}, {
		// "^a" matches nothing
		roles:  []string{"alpha", "beta", "gamma"},
		filter: "^a",
		want:   []string{"alpha"},
	}}

	for i, tt := range tests {
		roles := make([]string, len(tt.roles))
		copy(roles, tt.roles)
		got, err := filterRoles(roles, tt.filter)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%d: filterRoles(%q, %q): got %q, expected %q", i, tt.roles, tt.filter, got, tt.want)
		}
	}
}
