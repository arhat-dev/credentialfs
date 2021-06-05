package ui

import (
	"fmt"
	"os"

	"golang.org/x/term"

	"arhat.dev/credentialfs/pkg/pm"
)

func HandleCommandLineLoginInput(configName string) pm.LoginInputCallbackFunc {
	return func(t pm.TwoFactorKind, currentInput *pm.LoginInput) (*pm.LoginInput, error) {
		var (
			err    error
			result = currentInput
		)

		if result == nil {
			result = &pm.LoginInput{}
		}

		// handle login with username and password and filter out
		// unsupported 2FA methods
		switch t {
		case pm.TwoFactorKindNone, pm.TwoFactorKindOTP:
			if len(result.Username) == 0 {
				result.Username, err = requestCommandLineInput(
					fmt.Sprintf("Please enter your username for pm %q: ", configName),
					false,
				)
				if err != nil {
					return nil, fmt.Errorf("failed to read username: %w", err)
				}
			}

			if len(result.Password) == 0 {
				result.Password, err = requestCommandLineInput(
					fmt.Sprintf("Please enter your password for pm %q: ", configName),
					true,
				)
				if err != nil {
					return nil, fmt.Errorf("failed to read password: %w", err)
				}
			}

		// case pm.TwoFactorKindFIDO:
		// case pm.TwoFactorKindFIDO2:
		// case pm.TwoFactorKindU2F:
		default:
			return nil, fmt.Errorf("unsupported 2FA method %q", t)
		}

		// handle login with manual input for 2FA value
		if len(result.ValueFor2FA) == 0 {
			// nolint:gocritic
			switch t {
			case pm.TwoFactorKindOTP:
				result.ValueFor2FA, err = requestCommandLineInput(
					fmt.Sprintf("Please enter your OTP for pm %q: ", configName),
					false,
				)
				if err != nil {
					return nil, fmt.Errorf("failed to read OTP: %w", err)
				}
			}
		}

		// handle login without username and password
		// switch t {
		// case pm.TwoFactorKindFIDO:
		// case pm.TwoFactorKindFIDO2:
		// case pm.TwoFactorKindU2F:
		// }

		return result, nil
	}
}

func requestCommandLineInput(prompt string, hideInput bool) (string, error) {
	var (
		result string
	)

	_, err := fmt.Fprint(os.Stdout, prompt)
	if err != nil {
		return "", err
	}

	if hideInput {
		pwd, err2 := term.ReadPassword(int(os.Stdin.Fd()))
		if err2 != nil {
			return string(pwd), err2
		}

		result = string(pwd)
	} else {
		_, err = fmt.Fscanf(os.Stdin, "%s\n", &result)
		if err != nil {
			return "", err
		}
	}

	return result, nil
}
