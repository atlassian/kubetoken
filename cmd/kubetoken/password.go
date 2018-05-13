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
func getPassword(user string, promptPassword bool, skipKeyring bool) string {
	var password string

	// Attempt to get password from the keyring first
	if !promptPassword && !skipKeyring {
		password, err := getKeyringPassword(user)
		if err == nil {
			if *verbose {
				fmt.Printf("Got password from keyring for user %v\n", user)
			}
			return password
		}
		fmt.Printf("Warning: unable to get password from keyring, err: %v\n", err)
	} else if *verbose {
		fmt.Println("Skipping checking of keyring")
	}

	// Password was not found, prompt the user for it
	password = promptForPassword(user)

	// Save the password in the keyring
	if !skipKeyring {
		if err := setKeyringPassword(user, password); err != nil {
			fmt.Printf("Warning: unable to set password to keyring, err: %v\n", err)
		}
	} else if *verbose {
		fmt.Println("Skipping setting of keyring")
	}

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
