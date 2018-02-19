// kubetoken provides time limited access tokens to Kubernetes clusters.
package kubetoken

// Version is populated by the release process.
var Version string = "unknown"

// SearchBase is the LDAP search base.
var SearchBase string = "DC=example,DC=com"

// UserOU
var UserOU string = "OU=people"

// BotOU
var BotOU string = "OU=bots,OU=people"

// GroupOU
var GroupOU string = "OU=access,OU=groups"