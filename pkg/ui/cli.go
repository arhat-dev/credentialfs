package ui

import (
	"fmt"
	"os"

	"arhat.dev/pkg/iohelper"
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

		_, err = fmt.Fprintf(os.Stderr, "Login to pm %q\n", configName)
		if err != nil {
			return nil, err
		}

		// handle login with username and password and filter out
		// unsupported 2FA methods
		switch t {
		case pm.TwoFactorKindNone, pm.TwoFactorKindOTP:
			if len(result.Username) == 0 {
				result.Username, err = requestCommandLineInput(
					"username: ", false,
				)
				if err != nil {
					return nil, fmt.Errorf("failed to read username: %w", err)
				}
			}

			if len(result.Password) == 0 {
				result.Password, err = requestCommandLineInput(
					"password: ", true,
				)
				_, _ = fmt.Fprintln(os.Stderr)
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
					"one time password: ", false,
				)
				if err != nil {
					return nil, fmt.Errorf("failed to read otp: %w", err)
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

func requestCommandLineInput(prompt string, hideInput bool) ([]byte, error) {
	_, err := fmt.Fprint(os.Stderr, prompt)
	if err != nil {
		return nil, err
	}

	if hideInput {
		return term.ReadPassword(int(os.Stdin.Fd()))
	}

	return iohelper.ReadInputLine(os.Stdin)
}
