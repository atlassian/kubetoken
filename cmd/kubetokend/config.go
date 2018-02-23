package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"os"

	"github.com/atlassian/kubetoken"
	"github.com/pkg/errors"
)

type Context struct {
	CAClusterCert    string `json:"caclustercert"` // path to ca cert for kubernetes clusters
	CACert           string `json:"cacert"` // path to ca cert for kubetoken
	PrivKey          string `json:"privkey"` // path to ca cert private key for kubetoken
	caClusterCertPEM []byte // contents of the CAClusterCert file, as PEM.
	caCertPEM        []byte // contents of the CACert file, as PEM.
	Clusters         map[string]string `json:"clusters"`
	kubetoken.Signer `json:"-"`
}

type Environment struct {
	Name        string `json:"name"`
	Customer    string `json:"customer"`
	Environment string `json:"env"`
	Contexts    []Context `json:"contexts"`
}

type Config struct {
	Environments []Environment `json:"environments"`
}

func loadConfig(p string) (*Config, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var config Config
	dec := json.NewDecoder(f)
	if err := dec.Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}

func loadCertificates(c *Config) error {
	for i := range c.Environments {
		e := &c.Environments[i]
		for j := range e.Contexts {
			ctx := &e.Contexts[j]
			caCertPEM, err := ioutil.ReadFile(ctx.CACert)
			if err != nil {
				return errors.WithMessage(err, ctx.CACert)
			}
			privKeyPEM, err := ioutil.ReadFile(ctx.PrivKey)
			if err != nil {
				return errors.WithMessage(err, ctx.PrivKey)
			}

			block, _ := pem.Decode(caCertPEM)
			if block == nil {
				return errors.Errorf("%v: pem decode caCertPEM failed", ctx.CACert)
			}
			ctx.Signer.Cert, err = x509.ParseCertificate(block.Bytes)
			ctx.caCertPEM = caCertPEM
			if err != nil {
				return err
			}

			block, _ = pem.Decode(privKeyPEM)
			if block == nil {
				return errors.Errorf("%v: pem decode privKeyPEM failed", ctx.PrivKey)
			}
			ctx.Signer.PrivKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return err
			}

			if ctx.CAClusterCert != "" {
				caClusterCertPEM, err := ioutil.ReadFile(ctx.CAClusterCert)
				if err != nil {
					return errors.WithMessage(err, ctx.CAClusterCert)
				}
				block, _ = pem.Decode(caClusterCertPEM)
				if block == nil {
					return errors.Errorf("%v: pem decode caClusterCertPEM failed", ctx.CAClusterCert)
				}
				ctx.caClusterCertPEM = caClusterCertPEM
			} else {
				// If CAClusterCert is not set, use kubetoken CA as the cluster CA
				ctx.CAClusterCert = ctx.CACert
				ctx.caClusterCertPEM = ctx.caCertPEM
			}
		}
	}
	return nil
}
