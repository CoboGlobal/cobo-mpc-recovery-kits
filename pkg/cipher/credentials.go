package cipher

import (
	"fmt"
	"strings"
	"syscall"

	"golang.org/x/term"
)

func Credentials(prompt string) (string, error) {
	fmt.Print(prompt)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin)) //nolint:unconvert
	fmt.Print("\n")
	if err != nil {
		return "", fmt.Errorf("error read password from terminal: %w", err)
	}
	password := string(bytePassword)
	password = strings.TrimSpace(password)
	if password == "" {
		return "", fmt.Errorf("null password is not allowed")
	}
	if len(password) < 8 {
		return "", fmt.Errorf("password length too short")
	}
	return password, nil
}
