// Package oath provides functions to generate and verify OATH one-time
// passwords (OTP).
package oath

import (
	"crypto"
	"encoding/base32"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/ownmfa/hermes/pkg/consterr"
	"github.com/skip2/go-qrcode"
)

// Constants used to configure the OTP Algorithm field and URI.
const (
	HOTP string = "hotp"
	TOTP string = "totp"

	period int = 30
)

// Errors returned due to OTP validation failures.
const (
	ErrUnknownAlgorithm consterr.Error = "oath: unknown OATH algorithm"
	ErrHashSupport      consterr.Error = "oath: unsupported hash function"
	ErrDigitsRange      consterr.Error = "oath: digits outside supported range"
	ErrKeyLength        consterr.Error = "oath: insufficient key length"
	//#nosec G101 // false positive for hardcoded credentials
	ErrInvalidPasscode consterr.Error = "oath: invalid passcode"
)

// OTP represents a one-time password generator, and is compatible with both
// HOTP and TOTP algorithms. It uses a fixed time period of 30 seconds.
type OTP struct {
	Algorithm   string
	Hash        crypto.Hash
	Digits      int
	Key         []byte
	AccountName string
}

// Secret returns the key in base32 format without padding.
func (o *OTP) Secret() string {
	base32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding)

	return base32NoPad.EncodeToString(o.Key)
}

// validate validates OTP fields.
func (o *OTP) validate() error {
	switch o.Algorithm {
	case HOTP, TOTP:
		break
	default:
		return ErrUnknownAlgorithm
	}

	switch o.Hash {
	case crypto.SHA1, crypto.SHA256, crypto.SHA512:
		break
	default:
		return ErrHashSupport
	}

	if o.Digits < 6 || o.Digits > 10 {
		return ErrDigitsRange
	}

	if len(o.Key) < 16 {
		return ErrKeyLength
	}

	return nil
}

// uri generates a key URI in Google Authenticator-compatible format.
//
// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
//
// Example:
// otpauth://totp/Example:alice@google.com?secret=JBSW...&issuer=Example
func (o *OTP) uri(issuer string) (string, error) {
	if err := o.validate(); err != nil {
		return "", err
	}

	vals := url.Values{}
	vals.Set("secret", o.Secret())
	// Manually escape spaces due to Go not supporting percent-encoding in query
	// parameters:  https://github.com/golang/go/issues/4013
	vals.Set("issuer", strings.ReplaceAll(issuer, " ", "%20"))
	vals.Set("algorithm", strings.ReplaceAll(o.Hash.String(), "-", ""))
	vals.Set("digits", strconv.Itoa(o.Digits))

	switch o.Algorithm {
	case HOTP:
		vals.Set("counter", strconv.Itoa(0))
	case TOTP:
		vals.Set("period", strconv.Itoa(period))
	}

	uri := url.URL{
		Scheme: "otpauth",
		Host:   o.Algorithm,
		// Issuer in path will be automatically percent-encoded by uri.String().
		Path: strings.TrimSuffix(fmt.Sprintf("%s:%s", issuer, o.AccountName),
			":"),
		RawQuery: vals.Encode(),
	}

	// Manually unescape double-escaped spaces.
	return strings.ReplaceAll(uri.String(), "%2520", "%20"), nil
}

// QR generates a key QR code, in Google Authenticator-compatible format, as a
// PNG image.
func (o *OTP) QR(issuer string) ([]byte, error) {
	uri, err := o.uri(issuer)
	if err != nil {
		return nil, err
	}

	return qrcode.Encode(uri, qrcode.Medium, 200)
}
