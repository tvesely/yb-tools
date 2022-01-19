/*
Copyright © 2021 Yugabyte Support

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/term"
)

func MaskOut(value string) string {
	buf := strings.Builder{}

	for i := 0; i < len(value); i++ {
		buf.WriteRune('*')
	}

	return buf.String()
}

func PasswordPrompt() (string, error) {
	promptError := func(err error) (string, error) {
		return "", fmt.Errorf("unable to get password: %w", err)
	}
	fmt.Print("Enter password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return promptError(err)
	}
	fmt.Println()

	return string(password), nil
}

func NewPasswordPrompt() (string, error) {
	promptError := func(err error) (string, error) {
		return "", fmt.Errorf("unable to get password: %w", err)
	}
	fmt.Print("Enter password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return promptError(err)
	}
	fmt.Println()

	fmt.Print("Confirm password: ")
	confirmation, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return promptError(err)
	}
	if !bytes.Equal(password, confirmation) {
		return promptError(fmt.Errorf("passwords did not match"))
	}

	return string(password), nil
}

func ConfirmationDialog() error {
	var userInput string

	fmt.Print("Are you sure? (y/n): ")
	_, err := fmt.Scanln(&userInput)
	if err != nil {
		return err
	}
	switch strings.ToLower(userInput) {
	case "y", "yes":
		return nil
	case "n", "no":
		return fmt.Errorf("user declined confirmation dialog")
	default:
		return fmt.Errorf(`invalid input: must be "yes" or "no"`)
	}
}

func GetLogger(module string, debug bool) (logr.Logger, error) {
	level := zapcore.InfoLevel
	if debug {
		level = zapcore.DebugLevel
	}

	zc := zap.NewProductionConfig()

	zc.Level = zap.NewAtomicLevelAt(level)

	if !debug {
		zc.DisableStacktrace = true
		zc.Encoding = "console"
		zc.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}

	z, err := zc.Build()
	if err != nil {
		return logr.Logger{}, err
	}
	log := zapr.NewLogger(z).WithName(module)
	return log, nil
}
