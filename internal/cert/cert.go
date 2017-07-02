// Cert automates the generation of certificate and certificate authorities.
package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/pkg/errors"
)

const keySize = 2048

// NewCert generates a certificate/key pair.
func NewCert(caCertPEM, caKeyPEM []byte, expiry time.Time, cn string, extKeyUsage []x509.ExtKeyUsage) ([]byte, []byte, error) {
	cert, key, err := newCert(rand.Reader, caCertPEM, caKeyPEM, expiry, cn, extKeyUsage)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return certPEM, keyPEM, nil
}

func newCert(r io.Reader, caCertPEM, caKeyPEM []byte, expiry time.Time, cn string, extKeyUsage []x509.ExtKeyUsage) ([]byte, *rsa.PrivateKey, error) {
	tlsCert, err := tls.X509KeyPair(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	if len(tlsCert.Certificate) != 1 {
		return nil, nil, errors.New("more than one certificate for CA")
	}
	caCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, nil, err
	}

	if !caCert.BasicConstraintsValid || !caCert.IsCA {
		return nil, nil, errors.New("CA certificate is not a valid CA")
	}

	caKey, ok := tlsCert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("CA private key has unexpected type %T", tlsCert.PrivateKey)
	}
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate key: %v", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: newSerial(now),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore: now.UTC().AddDate(0, 0, -1),
		NotAfter:  expiry.UTC(),

		SubjectKeyId: bigIntHash(key.N),
		ExtKeyUsage:  []x509.ExtKeyUsage{
		//	x509.ExtKeyUsageAny,
		},
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	return cert, key, err
}

// NewCA generates a CA certificate/key pair.
func NewCA(cn string, expiry time.Time) ([]byte, []byte, error) {
	return newCA(rand.Reader, cn, expiry)
}

func newCA(r io.Reader, cn string, expiry time.Time) ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(r, keySize)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	serial := newSerial(now)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			SerialNumber: serial.String(),
		},
		NotBefore:    now.UTC().AddDate(0, 0, -1),
		NotAfter:     expiry.UTC(),
		SubjectKeyId: bigIntHash(key.N),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certPEMData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	keyPEMData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return certPEMData, keyPEMData, nil
}

func SignCSR(csr *x509.CertificateRequest, parent *x509.Certificate, privKey *rsa.PrivateKey) ([]byte, error) {
	certDER, err := signCSR(rand.Reader, csr, parent, privKey)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	return certPEM, nil

}

func signCSR(r io.Reader, csr *x509.CertificateRequest, parent *x509.Certificate, privKey *rsa.PrivateKey) ([]byte, error) {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: newSerial(now),
		Subject:      csr.Subject,
		NotBefore:    now.UTC().AddDate(0, 0, -1),
		NotAfter:     time.Now().UTC().Add(6 * time.Hour),
		SubjectKeyId: bigIntHash(privKey.N),
	}
	return x509.CreateCertificate(rand.Reader, template, parent, csr.PublicKey, privKey)
}

// NewCSR generates a CSR for CN=user,O=role
// It returns the CSR and private key in PEM format.
func NewCSR(user string, role string) ([]byte, []byte, error) {
	return newCSR(rand.Reader, user, role)
}

func newCSR(r io.Reader, user string, roles ...string) ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(r, keySize)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   user,
			Organization: roles,
		},
	}

	csrDER, err := x509.CreateCertificateRequest(r, template, key)
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return csrPEM, keyPEM, nil
}

func newSerial(now time.Time) *big.Int {
	return big.NewInt(int64(now.Nanosecond()))
}

func bigIntHash(n *big.Int) []byte {
	h := sha1.New()
	h.Write(n.Bytes())
	return h.Sum(nil)
}
