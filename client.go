package kubetoken

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

