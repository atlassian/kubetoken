// kubetokend handles requests for kubeconfig cert/key pairs.
// For the cli command, see kubetoken.
package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/atlassian/kubetoken"
	kingpin "gopkg.in/alecthomas/kingpin.v2"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

func main() {
	fmt.Println(os.Args[0], "version:", kubetoken.Version)

	ldapHost := kingpin.Flag("ldap", "ldap host to use (:636 assumed)").Required().String()
	configFile := kingpin.Flag("config", "path to kubetoken.json").Default("/config/kubetoken.json").String()
	kingpin.Parse()

	config, err := loadConfig(*configFile)
	if err != nil {
		log.Fatalf("could not load config: %v", err)
	}

	fmt.Print(os.Args[0], "loaded config: ")
	b, err := json.MarshalIndent(config, "", "  ")
	check(err)
	fmt.Printf("%s\n", b)

	if err := loadCertificates(config); err != nil {
		log.Fatalf("could not load certificates: %v", err)
	}

	r := mux.NewRouter()
	signer := http.Handler(&CertificateSigner{
		LDAPHost: *ldapHost,
		Config:   config,
	})
	if duoEnabled() {
		signer = DuoAuth(signer)
	}
	r.Handle("/api/v1/signcsr", BasicAuth(signer))
	r.Handle("/api/v1/roles", BasicAuth(&RoleHandler{
		ldaphost: *ldapHost,
	}))
	r.HandleFunc("/healthcheck", func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, "OK")
	})
	r.HandleFunc("/version", func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, kubetoken.Version)
	})

	loggedRouter := handlers.LoggingHandler(os.Stdout, r)

	addr := fmt.Sprintf(":%s", os.Getenv("PORT"))
	log.Println("listening on", addr)

	http.ListenAndServe(addr, loggedRouter)
}

type CertificateSigner struct {
	kubetoken.Signer
	LDAPHost string
	*Config
}

func userdn(user string) string {
	return fmt.Sprintf(binddn(user), escapeDN(user))
}

func binddn(user string) string {
	if strings.HasSuffix(user, "-bot") {
		return "CN=%s,OU=bots,OU=people,DC=office,DC=atlassian,DC=com"
	}
	return "CN=%s,OU=people,DC=office,DC=atlassian,DC=com"
}

func BasicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _, ok := req.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Authentication required", 401)
			return
		}
		next.ServeHTTP(w, req)
	})
}

func (s *CertificateSigner) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	user, pass, ok := req.BasicAuth()
	if !ok {
		http.Error(w, "Forbidden", 403)
		return
	}

	csr, err := readCSR(req.Body)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	if user != csr.Subject.CommonName {
		http.Error(w, fmt.Sprintf("Subject.CommonName %q does not match auth username %q", csr.Subject.CommonName, user), 403)
		return
	}
	role := csr.Subject.Organization[0]

	ad := kubetoken.ADRoleValidater{
		Bind: func() (kubetoken.LDAPConn, error) {
			ldapcreds := kubetoken.LDAPCreds{
				Host:     s.LDAPHost,
				Port:     636,
				BindDN:   userdn(user),
				Password: pass,
			}
			return ldapcreds.Bind()
		},
	}

	if err := ad.ValidateRoleForUser(user, role); err != nil {
		http.Error(w, err.Error(), 403)
		return
	}

	customer, ns, environ, err := parseCustomerNamespaceEnvFromRole(role)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}

	// find customer/environemnt for role
	var env *Environment
	for i := range s.Config.Environments {
		e := &s.Config.Environments[i]
		if e.Customer == customer && e.Environment == environ {
			env = e
			break
		}
	}
	if env == nil {
		http.Error(w, fmt.Sprintf("%s: no known environment", role), 400)
		return
	}

	certPEM, err := env.Contexts[0].Sign(csr)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// to support older clients, we push the cluster addresses from the
	// first context.
	var addresses []string
	for _, v := range env.Contexts[0].Clusters {
		addresses = append(addresses, v)
	}

	// sort lexically in the hope that cell-0 comes before cell-1, etc.
	sort.Stable(sort.StringSlice(addresses))

	var contexts []kubetoken.Context
	for _, c := range env.Contexts {
		contexts = append(contexts, kubetoken.Context{
			Files: map[string][]byte{
				"ca.pem":                    c.caCertPEM,
				fmt.Sprintf("%s.pem", user): certPEM,
			},
			Clusters: c.Clusters,
		})
	}

	enc := json.NewEncoder(w)
	enc.Encode(kubetoken.CertificateResponse{
		Username: user,
		Role:     csr.Subject.Organization[0],
		Files: map[string][]byte{
			"ca.pem":                    env.Contexts[0].caCertPEM,
			fmt.Sprintf("%s.pem", user): certPEM,
		},
		Customer:    env.Customer,
		Addresses:   addresses,
		Environment: env.Environment,
		Namespace:   ns,
		Contexts:    contexts,
	})
	log.Printf("authorised %v to assume role %v", csr.Subject.CommonName, csr.Subject.Organization[0])
}

type RoleHandler struct {
	ldaphost string
}

func (r *RoleHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	user, pass, ok := req.BasicAuth()
	if !ok {
		http.Error(w, "Forbidden", 403)
		return
	}

	ad := &kubetoken.ADRoleProvider{
		LDAPCreds: kubetoken.LDAPCreds{
			Host:     r.ldaphost,
			Port:     636,
			BindDN:   userdn(user),
			Password: pass,
		},
	}

	roles, err := ad.FetchRolesForUser(user)
	if err != nil {
		http.Error(w, err.Error(), 403)
		return
	}

	enc := json.NewEncoder(w)
	enc.Encode(struct {
		User  string   `json:"user"`
		Roles []string `json:"roles"`
	}{
		User:  user,
		Roles: roles,
	})
}

func readCSR(r io.Reader) (*x509.CertificateRequest, error) {
	csrPEM, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("unable to decode PEM block")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("expected CERTIFICATE REQUEST, got " + block.Type)
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

func parseCustomerNamespaceEnvFromRole(role string) (string, string, string, error) {
	re, err := regexp.Compile(`^kube-(?P<customer>\w+)-(?P<ns>\w+)-(?P<env>\w+)-dl-`)
	if err != nil {
		return "", "", "", err
	}
	m := re.FindStringSubmatch(role)
	if len(m) != 4 {
		return "", "", "", fmt.Errorf("no match for role %q", role)
	}
	var customer, ns, env string
	for i, name := range re.SubexpNames() {
		switch name {
		case "customer":
			customer = m[i]
		case "ns":
			ns = m[i]
		case "env":
			env = m[i]
		}
	}
	if customer == "" {
		return "", "", "", fmt.Errorf("customer not found in role %q", role)
	}
	if ns == "" {
		return "", "", "", fmt.Errorf("namespace not found in role %q", role)
	}
	if env == "" {
		return "", "", "", fmt.Errorf("environment not found in role %q", role)
	}
	return customer, ns, env, nil
}

// escapeDN returns a string with characters escaped to safely injected into a DN.
// Intended as a complement to ldap.EscapeFilter, which escapes ldap filter strings.
// Made with reference to https://www.owasp.org/index.php/LDAP_Injection_Prevention_Cheat_Sheet
// and http://www.rlmueller.net/CharactersEscaped.htm
func escapeDN(unsafe string) string {
	var buf bytes.Buffer
	for _, r := range unsafe {
		switch r {
		case '/', '\\', '#', ',', ';', '<', '>', '+', '=':
			buf.WriteRune('\\')
			fallthrough
		default:
			buf.WriteRune(r)
		}
	}
	return buf.String()
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
