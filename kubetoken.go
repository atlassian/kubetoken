// kubetoken provides time limited access tokens to Kubernetes clusters.
package kubetoken

// Version is populated by the release process.
var Version string = "unknown"

// SearchBase is the LDAP search base.
var SearchBase string = "DC=example,DC=com"

// Group prefix to use in ldap search
var SearchGroups string = "kube"

// NamespaceRegex is used to extract customer, namespace, and env from ldap queries
var NamespaceRegex string = `^kube-(?P<customer>\w+)-(?P<ns>\w+)-(?P<env>\w+)-dl-`

// UserOU
var UserOU string = "OU=people"

// BotOU
var BotOU string = "OU=bots,OU=people"

// GroupOU
var GroupOU string = "OU=access,OU=groups"