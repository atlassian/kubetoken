package main

import (
	"reflect"
	"testing"
)

func TestFilterRoles(t *testing.T) {
	tests := []struct {
		roles        []string
		filter       string
		keyWordsList []string
		want         []string
	}{{
		// special case
		roles:        []string{},
		filter:       ".",
		keyWordsList: []string{},
		want:         []string{},
	}, {
		// "" matches everthing
		roles:        []string{"alpha", "beta", "gamma"},
		filter:       "",
		keyWordsList: []string{},
		want:         []string{"alpha", "beta", "gamma"},
	}, {
		// "delta" matches nothing
		roles:        []string{"alpha", "beta", "gamma"},
		filter:       "delta",
		keyWordsList: []string{},
		want:         []string{},
	}, {
		// "^a" matches "alpha"
		roles:        []string{"alpha", "beta", "gamma"},
		filter:       "^a",
		keyWordsList: []string{},
		want:         []string{"alpha"},
	}, {
		// ["ga", "ma"] key words list matches "gamma"
		roles:        []string{"alpha", "beta", "gamma"},
		filter:       "",
		keyWordsList: []string{"ga", "ma"},
		want:         []string{"gamma"},
	}, {
		// filter and key words list specified at the same time
		// matches nothing in this case
		roles:        []string{"alpha", "beta", "gamma"},
		filter:       "^b",
		keyWordsList: []string{"al", "ha"},
		want:         []string{},
	}}

	for i, tt := range tests {
		roles := make([]string, len(tt.roles))
		copy(roles, tt.roles)
		got, err := filterRoles(roles, tt.filter, tt.keyWordsList)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%d: filterRoles(%q, %q): got %q, expected %q", i, tt.roles, tt.filter, got, tt.want)
		}
	}
}
