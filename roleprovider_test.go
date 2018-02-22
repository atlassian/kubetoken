package kubetoken

import "testing"

func TestBinddn(t *testing.T) {
	tests := []struct {
		role string
		want string
	}{{
		role: "aperson",
		want: "CN=%s,OU=people,DC=office,DC=atlassian,DC=com",
	}, {
		role: "abot",
		want: "CN=%s,OU=people,DC=office,DC=atlassian,DC=com",
	}, {
		role: "a-bot",
		want: "CN=%s,OU=bots,OU=people,DC=office,DC=atlassian,DC=com",
	}}

	SearchBase = "DC=office,DC=atlassian,DC=com"
	for _, tt := range tests {
		got := binddn(tt.role)
		if got != tt.want {
			t.Errorf("binddn(%q): got: %q, want: %q", tt.role, got, tt.want)
		}
	}
}
