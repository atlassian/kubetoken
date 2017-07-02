package kubetoken

import "testing"

func TestSplit(t *testing.T) {
	tests := []struct {
		input                                  string
		customer, environment, namespace, role string
	}{{
		input:       "kube-kitt-default-dev-dl-sysadmin",
		customer:    "kitt",
		environment: "dev",
		namespace:   "default",
		role:        "sysadmin",
	}}

	for _, tt := range tests {
		c, e, n, r := split(tt.input)
		if c != tt.customer || e != tt.environment || n != tt.namespace || r != tt.role {
			t.Errorf("split(%q): expected: %s, %s, %s, %s, got: %s, %s, %s, %s",
				tt.input,
				tt.customer, tt.environment, tt.namespace, tt.role,
				c, e, n, r,
			)
		}
	}
}
