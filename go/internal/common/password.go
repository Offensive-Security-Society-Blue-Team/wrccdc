package common

import (
	"crypto/rand"
	"math/big"
	"strings"
)

// Character classes. Ambiguous characters (0/O, 1/l/I) are intentionally
// excluded so operators can read and re-type rotated passwords without error
// during an incident.
const (
	Lower  = "abcdefghijkmnopqrstuvwxyz" // no l
	Upper  = "ABCDEFGHJKLMNPQRSTUVWXYZ"  // no I, O
	Digits = "23456789"                  // no 0, 1
	// Symbols that are safe to pass as exec arguments (we never shell out with
	// the password in a command string) and safe inside single-quoted SQL
	// literals (no single quote, no backslash, no backtick).
	Symbols = "!@#$%^*()-_=+[]{}"
)

// GenOptions controls password generation.
type GenOptions struct {
	Length  int
	Symbols bool // include symbol class
}

// DefaultGen returns strong defaults for human-rotated passwords.
func DefaultGen() GenOptions { return GenOptions{Length: 20, Symbols: true} }

// SafeGen returns alphanumeric-only options, used where a downstream sink
// (some SQL clients, config files) is picky about punctuation.
func SafeGen() GenOptions { return GenOptions{Length: 24, Symbols: false} }

// Generate returns a cryptographically random password that always contains at
// least one lowercase, one uppercase and one digit (and one symbol when
// symbols are enabled). It never panics; on the (practically impossible) event
// that the system RNG fails it falls back to returning what it has.
func Generate(opt GenOptions) string {
	if opt.Length < 8 {
		opt.Length = 8
	}
	pool := Lower + Upper + Digits
	required := []string{Lower, Upper, Digits}
	if opt.Symbols {
		pool += Symbols
		required = append(required, Symbols)
	}

	out := make([]byte, 0, opt.Length)
	// guarantee one of each required class
	for _, class := range required {
		out = append(out, pick(class))
	}
	for len(out) < opt.Length {
		out = append(out, pick(pool))
	}
	shuffle(out)
	return string(out)
}

func pick(set string) byte {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return set[0]
	}
	return set[n.Int64()]
}

// shuffle performs a crypto-random Fisher-Yates shuffle in place.
func shuffle(b []byte) {
	for i := len(b) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			continue
		}
		j := int(n.Int64())
		b[i], b[j] = b[j], b[i]
	}
}

// Sanitize trims whitespace that some sources inject; purely defensive.
func Sanitize(s string) string { return strings.TrimSpace(s) }
