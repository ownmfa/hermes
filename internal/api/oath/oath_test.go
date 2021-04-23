// +build !integration

package oath

import (
	"crypto"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"net/url"
	"testing"

	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/stretchr/testify/require"
)

func TestSecret(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	otp := &OTP{Key: key}

	base32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding)
	require.Equal(t, base32NoPad.EncodeToString(otp.Key), otp.Secret())
}

func TestUri(t *testing.T) {
	t.Parallel()

	key, err := hex.DecodeString("b76c5da0d71b5646ed38b483532cded2622d072a5d1" +
		"75030b6540169b7380d58")
	require.NoError(t, err)

	b32Key := "W5WF3IGXDNLEN3JYWSBVGLG62JRC2BZKLULVAMFWKQAWTNZYBVMA"

	issuer := random.String(10)
	username := random.Email()

	tests := []struct {
		inpHash     crypto.Hash
		inpKey      []byte
		inpDigits   int
		inpType     string
		inpIssuer   string
		inpUsername string
		res         string
		err         error
	}{
		{
			crypto.SHA1, key, 6, "hotp", issuer, username, "otpauth://hotp/" +
				issuer + ":" + username + "?algorithm=SHA1&counter=0&digits=6" +
				"&issuer=" + issuer + "&secret=" + b32Key, nil,
		},
		{
			crypto.SHA256, key, 7, "totp", issuer, username, "otpauth://totp/" +
				issuer + ":" + username + "?algorithm=SHA256&digits=7&issuer=" +
				issuer + "&period=30&secret=" + b32Key, nil,
		},
		{
			crypto.SHA512, key, 8, "hotp", "Company ABC", username,
			"otpauth://hotp/Company%20ABC:" + username + "?algorithm=SHA512&" +
				"counter=0&digits=8&issuer=Company%20ABC&secret=" + b32Key, nil,
		},
		{
			crypto.SHA512, key, 9, "totp", issuer, username, "otpauth://totp/" +
				issuer + ":" + username + "?algorithm=SHA512&digits=7&issuer=" +
				issuer + "&period=30&secret=" + b32Key, nil,
		},
		{
			crypto.SHA1, nil, 7, "", "", "", "", ErrKeyLength,
		},
	}

	for _, test := range tests {
		lTest := test

		t.Run(fmt.Sprintf("Can generate %+v", lTest), func(t *testing.T) {
			t.Parallel()

			otp := &OTP{
				Hash: lTest.inpHash, Key: lTest.inpKey, Digits: lTest.inpDigits,
			}

			res, err := otp.uri(lTest.inpType, lTest.inpIssuer,
				lTest.inpUsername)
			t.Logf("res, err: %v, %v", res, err)
			require.Equal(t, lTest.res, res)
			require.Equal(t, lTest.err, err)

			uri, err := url.Parse(res)
			t.Logf("uri, err: %#v, %v", uri, err)
			require.NoError(t, err)
		})
	}
}

func TestQR(t *testing.T) {
	t.Parallel()

	key, err := hex.DecodeString("b76c5da0d71b5646ed38b483532cded2622d072a5d1" +
		"75030b6540169b7380d58")
	require.NoError(t, err)

	issuer := random.String(10)
	username := random.Email()

	tests := []struct {
		inpHash     crypto.Hash
		inpKey      []byte
		inpDigits   int
		inpType     string
		inpIssuer   string
		inpUsername string
		err         error
	}{
		{crypto.SHA1, key, 6, "hotp", issuer, username, nil},
		{crypto.SHA256, key, 7, "totp", issuer, username, nil},
		{crypto.SHA512, key, 8, "hotp", "Company ABC", username, nil},
		{crypto.SHA1, nil, 7, "", "", "", ErrKeyLength},
	}

	for _, test := range tests {
		lTest := test

		t.Run(fmt.Sprintf("Can generate %+v", lTest), func(t *testing.T) {
			t.Parallel()

			otp := &OTP{
				Hash: lTest.inpHash, Key: lTest.inpKey, Digits: lTest.inpDigits,
			}

			res, err := otp.QR(lTest.inpType, lTest.inpIssuer, lTest.inpUsername)
			t.Logf("res, err: %x, %v", res, err)
			if lTest.err == nil {
				require.Greater(t, len(res), 800)
			}
			require.Equal(t, lTest.err, err)
		})
	}
}
