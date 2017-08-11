# Installation

This page describes the steps necessary to customise kubetoken for your environment.

## Linker variables

To avoid the necessity for a configuration file to be distributed alongside kubetoken, the default value of the variables for 

- LDAP search base
- kubetoken host

are set to dummy values in the source.
When building `kubetoken` and `kubetokend` you _must_ use the `-X` linker flag to overwrite those values with site specific values.

**You cannot skip this step**

By default kubetoken compiles against dummy example.com domain names, you cannot build kubetoken without applying linker variables specific for your environment.

### Set the kubetokend host address

To set the kubetokend host address when building `cmd/kubetoken`, set the address using the linker flag
```
-X main.kubetokend=https://kubetoken.yourcluster.yourcompany.com
```

### Set the LDAP search base

To set the LDAP search base when building `cmd/kubetoken` _and_ `cmd/kubetokend`, set the address using the linker flag
```
-X github.com/atlassian/kubetoken.SearchBase=DC=yourcompany,DC=com
```

You _must_ set the LDAP search base for both`cmd/kubetoken` _and_ `cmd/kubetokend`.

## DUO two factor authentication

Kubetoken supports 2fa via the DUO. This feature is disabled by default. To enable this feature set the following three flags in your kubetokend deployment

- `--duoikey` (defaults to `DUO_IKEY`)
- `--duoskey` (defaults to `DUO_SKEY`)
- `--duoapihost` (defaults to `DUO_API_HOST`)

All three values can be retrieved from the admin console by someone with Duo administration rights for your organisation.

## kubetoken cli

Once built, `kubetoken` can be distributed to your users as a single binary.

## kubetokend deployment

If you are planning on deploying kubetoken inside kubernetes you will need to do the following.

1. Build and upload a Docker image of `kubetokend`. A sample [Dockerfile](DOCKERFILE.example) is provided in this repository.
2. Deploy `kubetokend` to your cluster. A sample [deployment manifest](deployment/) is provided in this repository. You will need to add secrets for each pair of CA certificate and private keys for each cluster you wish to use.
   ```
   kubectl create secret generic -n $NAMESPACE $NAME --from-file=ca.pem --from-file=ca-key.pem
   ```
   
