/*
Copyright 2026.

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

// Package password generates random passwords.
package password

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

const (
	lower   = "abcdefghijklmnopqrstuvwxyz"
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits  = "0123456789"
	symbols = "!#$%&()*+,-./:;<=>?@[]^_{|}~'\"\\`"
)

// MinLength is the shortest password Generate produces.
const MinLength = 16

// Generate returns a random password of the given length using printable ASCII
// characters except those in exclude. The password contains at least one lower
// case letter, upper case letter and digit, and one symbol if any are allowed.
func Generate(length int, exclude string) (string, error) {
	if length < MinLength {
		return "", fmt.Errorf("password length %d is below the minimum of %d", length, MinLength)
	}

	classes := make([]string, 0, 4)
	for _, set := range []string{lower, upper, digits, symbols} {
		if s := strip(set, exclude); s != "" {
			classes = append(classes, s)
		}
	}
	if len(classes) < 3 || strip(lower, exclude) == "" || strip(upper, exclude) == "" || strip(digits, exclude) == "" {
		return "", errors.New("excludeCharacters removes all letters or digits of a class")
	}
	all := strings.Join(classes, "")

	out := make([]byte, length)
	// One character from each class, the rest from all allowed characters.
	for i, set := range classes {
		c, err := pick(set)
		if err != nil {
			return "", err
		}
		out[i] = c
	}
	for i := len(classes); i < length; i++ {
		c, err := pick(all)
		if err != nil {
			return "", err
		}
		out[i] = c
	}
	if err := shuffle(out); err != nil {
		return "", err
	}
	return string(out), nil
}

func strip(set, exclude string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(exclude, r) {
			return -1
		}
		return r
	}, set)
}

func pick(set string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, fmt.Errorf("read random: %w", err)
	}
	return set[n.Int64()], nil
}

// shuffle is a Fisher-Yates shuffle using crypto/rand.
func shuffle(b []byte) error {
	for i := len(b) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return fmt.Errorf("read random: %w", err)
		}
		j := n.Int64()
		b[i], b[j] = b[j], b[i]
	}
	return nil
}
