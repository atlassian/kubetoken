package main

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	var cleanup []func(*testing.T)
	defer func() {
		for _, fn := range cleanup {
			fn(t)
		}
	}()

	mkjson := func(contents string) string {
		f, err := ioutil.TempFile("", "config_test")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		cleanup = append(cleanup, func(t *testing.T) {
			err := os.Remove(f.Name())
			if err != nil {
				t.Error(err)
			}
		})
		if _, err := io.WriteString(f, contents); err != nil {
			t.Fatal(err)
		}
		return f.Name()
	}

	_ = mkjson

	tests := []struct {
		path string
		want *Config
		err  error
	}{{
		path: "/missing/file",
		err: &os.PathError{
			Op:   "open",
			Path: "/missing/file",
			Err:  syscall.ENOENT,
		},
	}, {
		path: mkjson("this ain't json"),
		err:  jsonError("this ain't json"),
	}, {
		path: mkjson(`{
			"environments": "missing"
		}`),
		err: jsonError(`{
			"environments": "missing"
	        }`, new(Config)),
	}, {
		path: mkjson(`{
			  "environments": [
			      {
				  "customer": "example",
				  "env": "dev",
				  "contexts": [
				     {
					"clusters": {
				            "example": "https://example.com"
					},
			                "caclustercert": "/ssl/example-cluster/ca.pem",
			                "cacert": "/ssl/example-dev/ca.pem",
			                "privkey": "/ssl/example-dev/ca-key.pem"
			             }
				  ]    
			      }]
		         }`),
		want: &Config{
			Environments: []Environment{{
				Customer:    "example",
				Environment: "dev",
				Contexts: []Context{{
					CAClusterCert: "/ssl/example-cluster/ca.pem",
					CACert: "/ssl/example-dev/ca.pem",
					PrivKey: "/ssl/example-dev/ca-key.pem",
					Clusters: map[string]string{
					    "example": "https://example.com",
					},
				}},
			}},
		},
	},
	{
		path: mkjson(`{
			  "environments": [
			      {
                      "customer": "example",
                      "env": "dev",
                      "contexts": [
                         {
                            "clusters": {
                            	"example": "https://example.com"
                            },
                            "cacert": "/ssl/example-dev/ca.pem",
                            "privkey": "/ssl/example-dev/ca-key.pem"
                        }
                      ]
			      }]
		         }`),
		want: &Config{
			Environments: []Environment{{
				Customer:    "example",
				Environment: "dev",
				Contexts: []Context{{
					CAClusterCert: "",
					CACert: "/ssl/example-dev/ca.pem",
					PrivKey: "/ssl/example-dev/ca-key.pem",
					Clusters: map[string]string{
					    "example": "https://example.com",
					},
				}},
			}},
		},
	}}

	for i, tt := range tests {
		got, err := loadConfig(tt.path)
		if !reflect.DeepEqual(err, tt.err) {
			t.Errorf("%d: got err: %#v, expected err: %#v", i, err, tt.err)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%d: got: %#v, expected: %#v", i, got, tt.want)
			continue
		}
	}
}

func jsonError(buf string, v ...interface{}) error {
	var m interface{}
	if len(v) > 0 {
		m = v[0]
	}
	dec := json.NewDecoder(strings.NewReader(buf))
	return dec.Decode(&m)
}
