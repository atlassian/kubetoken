package cert

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"
	"time"
)

func TestNewLeaf(t *testing.T) {
	caCertPEM := readFile(t, "_testdata/ssl/ca.pem")
	caKeyPEM := readFile(t, "_testdata/ssl/ca-key.pem")

	expiry := time.Now().Add(time.Hour)
	const cn = "dcheney"
	certPEM, _, err := NewCert(caCertPEM, caKeyPEM, expiry, cn, nil)
	if err != nil {
		t.Fatal(err)
	}
	cert := parseCertificate(t, certPEM)
	ca := parseCertificate(t, caCertPEM)
	if err := cert.CheckSignatureFrom(ca); err != nil {
		t.Fatal("cert", cert.Subject, "not signed by", ca.Subject, err)
	}
}

func TestNewCA(t *testing.T) {
	cn := "kube-ca"
	expiry := time.Now().Add(time.Hour)

	_, _, err := NewCA(cn, expiry)
	if err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) []byte {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parseCertificate(t *testing.T, buf []byte) *x509.Certificate {
	block, _ := pem.Decode(buf)
	certs, err := x509.ParseCertificates(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatal("expected 1 cert, got", len(certs))
	}
	return certs[0]
}
