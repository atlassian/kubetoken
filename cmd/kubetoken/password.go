package main

import (
	"fmt"
	"github.com/howeyc/gopass"
	"github.com/zalando/go-keyring"
	"os"
)

const keyringService = "kubetoken"

// getPassword handles the flow for getting a password from the user
// Attempts to get the password from the keyring first, then prompts
// Saves the prompted password to the keyring
func getPassword(user string, skipKeyringFetch bool) string {
	var password string

	// Attempt to get password from the keyring first
	if !skipKeyringFetch {
		password, err := getKeyringPassword(user)
		if err != nil && err != keyring.ErrNotFound {
			check(err)
		}
		if err == nil {
			if *verbose {
				fmt.Printf("Got password from keyring for user %v\n", user)
			}
			return password
		}
	}

	if *verbose && skipKeyringFetch {
		fmt.Println("Skipping checking of keyring")
	}

	// Password was not found, prompt the user for it
	// Save the password in the keyring
	password = promptForPassword(user)
	check(setKeyringPassword(user, password))
	return password
}

// promptForPassword prompts the user for their password
func promptForPassword(user string) string {
	if *verbose {
		fmt.Println("Prompting user for password")
	}
	prompt := fmt.Sprintf("Staff ID password for %s: ", user)
	pw, err := gopass.GetPasswdPrompt(prompt, false, os.Stdin, os.Stdout)
	check(err)
	return string(pw)
}

// getKeyringPassword attempts to get the password from the keyring
func getKeyringPassword(user string) (string, error) {
	if *verbose {
		fmt.Printf("Getting password from keyring for service %v, user %v\n", keyringService, user)
	}
	return keyring.Get(keyringService, user)
}

// setKeyringPassword sets the password in the keyring
func setKeyringPassword(user string, password string) error {
	if *verbose {
		fmt.Printf("Setting password in keyring for service %v, user %v\n", keyringService, user)
	}
	return keyring.Set(keyringService, user, password)
}
