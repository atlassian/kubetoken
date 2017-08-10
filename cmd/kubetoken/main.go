package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"

	kingpin "gopkg.in/alecthomas/kingpin.v2"

	"github.com/atlassian/kubetoken"
	"github.com/atlassian/kubetoken/internal/cert"
	"github.com/pkg/errors"

	"github.com/howeyc/gopass"
)

// this value can be overwritten by -ldflags="-X main.kubetokend=$URL"
var kubetokend = "https://kubetoken.example.com"

var (
	verbose  = kingpin.Flag("verbose", "talk, damnit").Short('v').Bool()
	dumpJson = kingpin.Flag("json", "dump json").Short('j').Bool()
)

func main() {
	var (
		user       = kingpin.Flag("user", "StaffID username.").Short('u').Default(os.Getenv("USER")).String()
		kubeconfig = kingpin.Flag("kubeconfig", "kubeconfig location.").Default(filepath.Join(os.Getenv("HOME"), ".kube", "config")).String()
		version    = kingpin.Flag("version", "print version string and exit.").Bool()
		filter     = kingpin.Flag("filter", "only show matching roles.").Short('f').String()
		namespace  = kingpin.Flag("namespace", "override namespace.").Short('n').String()
		host       = kingpin.Flag("host", "kubetokend hostname.").Short('h').Default(kubetokend).String()
		pass       = kingpin.Flag("password", "password.").Short('P').Default(os.Getenv("KUBETOKEN_PW")).String()
	)
	kingpin.Parse()

	if *version {
		compareVersionsAndExit(*host)
	}

	checkKubectlOrExit()

	if *pass == "" {
		fmt.Printf("Staff ID password for %s: ", *user)
		pw, err := gopass.GetPasswd()
		check(err)
		*pass = string(pw)
	}

	// fetch available roles to check the staffid password
	// provided
	roles, err := fetchRoles(*host, *user, *pass)
	check(err)

	roles, err = filterRoles(roles, *filter)
	check(err)
	sort.Strings(roles)

	// pick or choose a role
	var role string
	switch len(roles) {
	case 0:
		fatalf("no matching role found; you must construct additional pylons")
	case 1:
		role = roles[0]
		fmt.Printf("Auto selecting matching role: %s\n", role)
	default:
		role, err = chooseRole(roles)
		check(err)
	}

	// now we know our name, and the role, generate a csr
	csr, privkey, err := cert.NewCSR(*user, role)
	check(err)

	// send certificate to kubetoken for validation and signature
	uri := *host + "/api/v1/signcsr"
	result, err := submitCSR(uri, *user, *pass, csr)
	check(err)

	// because we send a CSR to kubetokend, only we know the private key.
	// fake this by putting it into the result.Files section as if
	// kubetokend sent it to the client.
	result.Files[fmt.Sprintf("%s-key.pem", *user)] = privkey

	err = processCertificateResponse(*kubeconfig, result, *namespace)
	check(err)
}

func fetchRoles(host, user, pass string) ([]string, error) {
	// fetch available roles for user from kubetokend
	req, err := http.NewRequest("GET", host+"/api/v1/roles", nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(user, pass)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("remote server replied: %v", resp.Status)
	}
	dec := json.NewDecoder(resp.Body)
	var v struct {
		Roles []string `json:"roles"`
	}
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v.Roles, nil
}

func submitCSR(uri string, user, pass string, csr []byte) (*kubetoken.CertificateResponse, error) {
	req, err := http.NewRequest("POST", uri, bytes.NewReader(csr))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(user, pass)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 200:
		return decodeResponseBody(resp.Body)
	case 399:
		// this is a special case where the client should be redirected to duo auth endpoint
		u, err := url.Parse(uri)
		if err != nil {
			return nil, err
		}
		uri = fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, resp.Header.Get("Location"))
		fmt.Println("Awaiting DUO Auth.")
		return submitCSR(uri, user, pass, csr)
	default:
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.Errorf("expected 200, got %v\n%s", resp.Status, body)
	}
}

func decodeResponseBody(r io.Reader) (*kubetoken.CertificateResponse, error) {
	if *dumpJson {
		r = io.TeeReader(r, os.Stdout)
	}
	dec := json.NewDecoder(r)
	var result kubetoken.CertificateResponse
	err := dec.Decode(&result)
	return &result, err
}

func chooseRole(roles []string) (string, error) {
	fmt.Println("Available roles to choose from")
	for i, r := range roles {
		fmt.Printf("\t%d. %s\n", i+1, r)
	}
	fmt.Print("\nEnter number of role you want: ")

	var n int
	_, err := fmt.Scanln(&n)
	if err != nil {
		return "", err
	}
	if n < 1 || n > len(roles) {
		return "", fmt.Errorf("value %d out of range", n)
	}
	n--
	return roles[n], nil
}

func filterRoles(roles []string, filter string) ([]string, error) {
	re, err := regexp.Compile(filter)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(roles); {
		if re.MatchString(roles[i]) {
			i++
			continue
		}
		// role does not match
		roles[i] = roles[len(roles)-1]
		roles = roles[:len(roles)-1]
	}
	return roles, nil
}

func processCertificateResponse(kubeconfig string, result *kubetoken.CertificateResponse, namespace string) error {
	kubeconfigdir := filepath.Dir(kubeconfig)
	credentials := fmt.Sprintf("%s/%s", result.Role, result.Username)
	certsdir := filepath.Join(kubeconfigdir, "certs", result.Role)

	usercert := fmt.Sprintf("%s.pem", result.Username)
	usercertfile := filepath.Join(certsdir, usercert)
	if err := writeFile(usercertfile, result.Files[usercert]); err != nil {
		return err
	}
	userkey := fmt.Sprintf("%s-key.pem", result.Username)
	userkeyfile := filepath.Join(certsdir, userkey)
	if err := writeFile(userkeyfile, result.Files[userkey]); err != nil {
		return err
	}

	// override server provided namespace if requested.
	if namespace == "" {
		namespace = result.Namespace
	}

	defaultCtx := "\xff" // see explanation below
	for _, ctx := range result.Contexts {
		if err := run("kubectl",
			"--kubeconfig", kubeconfig,
			"config",
			"set-credentials", credentials,
			"--client-key", userkeyfile,
			"--client-certificate", usercertfile); err != nil {
			return err
		}
		cafile := filepath.Join(certsdir, "ca.pem")
		if err := writeFile(cafile, result.Files["ca.pem"]); err != nil {
			return err
		}

		if len(ctx.Clusters) == 0 {
			return fmt.Errorf("no clusters provided for Customer: %q, Environment: %q, Role: %q", result.Customer, result.Environment, result.Role)
		}

		for name, a := range ctx.Clusters {
			cluster := hostnameFromURL(a)
			if err := run("kubectl",
				"--kubeconfig", kubeconfig,
				"config",
				"set-cluster", cluster,
				"--server", a,
				"--certificate-authority", cafile); err != nil {
				return err
			}
			context := fmt.Sprintf("%s/%s/%s", result.Role, name, result.Username)

			if err := run("kubectl",
				"--kubeconfig", kubeconfig,
				"config",
				"set-context", context,
				"--cluster", cluster,
				"--user", credentials,
				"--namespace", namespace); err != nil {
				return err
			}

			// this is a cheap hack to avoid collecting all the names of cluster cells
			// then sorting them.
			if context < defaultCtx {
				// if the name of the cluster sorts before the current one, overwrite
				// defaultCtx. In the first iteration of the loop, defaultCtx is set
				// to \xff which is unprintable, so very unlikely to be a cell name, yet
				// because it sorts _after_ any printable character will be overwritten
				// by the first iteration of the loop.
				defaultCtx = context
			}
		}
	}
	if err := run("kubectl",
		"--kubeconfig", kubeconfig,
		"config",
		"use-context", defaultCtx); err != nil {
		return err
	}

	return nil
}

func compareVersionsAndExit(host string) {
	versionURL := host + "/version"
	resp, err := http.Get(versionURL)
	check(err)
	if resp.StatusCode != 200 {
		fatalf("unexpected status code fetching %s: %v", versionURL, resp.Status)
	}
	remoteVersion := readBodyAsString(resp.Body)
	fmt.Println(kubetoken.Version)
	if remoteVersion != kubetoken.Version {
		fmt.Fprintf(os.Stderr, "Remote kubetoken version, %s, does not match local version, %s. Perhaps an upgrade is in order.\n", remoteVersion, kubetoken.Version)
	}
	os.Exit(0)
}

func checkKubectlOrExit() {
	if _, err := exec.LookPath("kubectl"); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		switch runtime.GOOS {
		case "darwin":
			fmt.Fprintf(os.Stderr, "Install kubectl with brew install kubectl\n")
		default:
			fmt.Fprintf(os.Stderr, "Please follow the instructions here, https://coreos.com/kubernetes/docs/latest/configure-kubectl.html\n")
		}
		os.Exit(1)
	}
}

func readBodyAsString(rc io.ReadCloser) string {
	defer rc.Close()
	b, err := ioutil.ReadAll(rc)
	check(err)
	return string(b)
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return ioutil.WriteFile(path, data, 0600)
}

func run(arg0 string, args ...string) error {
	cmd := exec.Command(arg0, args...)
	if *verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	// fmt.Fprintf(os.Stderr, "+ %s\n", strings.Join(cmd.Args, " "))
	return cmd.Run()
}

func check(err error) error {
	if err != nil {
		fatalf("%v", err)
	}
	return err
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "fatal: "+format+"\n", args...)
	os.Exit(1)
}

// hostnameFromURL returns the hostname from a url.
// it calls fatal if the url cannot be parsed.
func hostnameFromURL(raw string) string {
	u, err := url.Parse(raw)
	check(err)
	return u.Host
}
