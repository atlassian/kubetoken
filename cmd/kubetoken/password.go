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
	if promptPassword {
		password = promptForPassword(user)
		if !skipKeyring {
			setKeyringPassword(user, password)
		}
	} else if skipKeyring {
		password = promptForPassword(user)
	} else {
		var err error
		password, err = getKeyringPassword(user)
		if err != nil {
			password = promptForPassword(user)
			setKeyringPassword(user, password)
		}
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
	password, err := keyring.Get(keyringService, user)
	if *verbose && err != nil {
		fmt.Printf("Warning: error whilst getting password from keyring: %v\n", err)
	}
	return password, err
}

// setKeyringPassword sets the password in the keyring
func setKeyringPassword(user string, password string) error {
	if *verbose {
		fmt.Printf("Setting password in keyring for service %v, user %v\n", keyringService, user)
	}
	err := keyring.Set(keyringService, user, password)
	if *verbose && err != nil {
		fmt.Printf("Warning: error whilst setting password to keyring: %v\n", err)
	}
	return err
}
