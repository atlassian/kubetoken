package kubetoken

import "regexp"

type CertificateResponse struct {
	Username    string            `json:"username"`
	Role        string            `json:"role"`
	Files       map[string][]byte `json:"files"`
	Addresses   []string          `json:"addresses"`
	Customer    string            `json:"customer"`
	Environment string            `json:"environment"`
	Namespace   string            `json:"namespace"`
	Contexts    []Context         `json:"contexts"`
}

type Context struct {
	Files    map[string][]byte `json:"files"`
	Clusters map[string]string `json:"clusters"`
}

var splitRE = regexp.MustCompile(`^kube-(?P<customer>\w+)-(?P<namespace>\w+)-(?P<environment>\w+)-dl-(?P<role>\w+)$`)

// split parses a role into its component customer, environment, role, and namespace
func split(role string) (string, string, string, string) {
	match := splitRE.FindStringSubmatch(role)
	return match[1], match[3], match[2], match[4]
}
