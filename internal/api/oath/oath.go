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
	"time"

	"github.com/ownmfa/hermes/pkg/consterr"
	"github.com/skip2/go-qrcode"
)

const (
	ErrKeyLength consterr.Error = "oath: insufficient key length"
	//#nosec G101 // false positive for hardcoded credentials
	ErrInvalidPasscode consterr.Error = "oath: invalid passcode"
	period                            = 30 * time.Second
)

// OTP represents a one-time password generator, and is compatible with both
// HOTP and TOTP algorithms. It uses a fixed time period of 30 seconds.
type OTP struct {
	Hash   crypto.Hash
	Key    []byte
	Digits int
}

// Secret returns the key in base32 format without padding.
func (o *OTP) Secret() string {
	base32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding)

	return base32NoPad.EncodeToString(o.Key)
}

// uri generates a key URI in Google Authenticator-compatible format. The value
// of keyType should be either "hotp" or "totp".
//
// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
//
// Example:
// otpauth://totp/Example:alice@google.com?secret=JBSW...&issuer=Example
func (o *OTP) uri(keyType, issuer, username string) (string, error) {
	if len(o.Key) < 16 {
		return "", ErrKeyLength
	}

	if o.Digits < 6 || o.Digits > 8 {
		o.Digits = 7
	}

	vals := url.Values{}
	vals.Set("secret", o.Secret())
	// Manually escape spaces due to Go not supporting percent-encoding in query
	// parameters:  https://github.com/golang/go/issues/4013
	vals.Set("issuer", strings.ReplaceAll(issuer, " ", "%20"))
	vals.Set("algorithm", strings.ReplaceAll(o.Hash.String(), "-", ""))
	vals.Set("digits", strconv.Itoa(o.Digits))

	switch keyType {
	case "totp":
		vals.Set("period", strconv.FormatInt(int64(period/time.Second), 10))
	default:
		vals.Set("counter", strconv.Itoa(0))
	}

	uri := url.URL{
		Scheme: "otpauth",
		Host:   keyType,
		// Issuer in path will be automatically percent-encoded by uri.String().
		Path:     fmt.Sprintf("%s:%s", issuer, username),
		RawQuery: vals.Encode(),
	}

	// Manually unescape double-escaped spaces.
	return strings.ReplaceAll(uri.String(), "%2520", "%20"), nil
}

// QR generates a key QR code, in Google Authenticator-compatible format, as a
// PNG image. The value of keyType should be either "hotp" or "totp".
func (o *OTP) QR(keyType, issuer, username string) ([]byte, error) {
	uri, err := o.uri(keyType, issuer, username)
	if err != nil {
		return nil, err
	}

	return qrcode.Encode(uri, qrcode.Medium, 200)
}
