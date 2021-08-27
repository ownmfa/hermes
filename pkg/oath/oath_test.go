//go:build !integration

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

func TestValidate(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	tests := []struct {
		inpAlg    string
		inpHash   crypto.Hash
		inpDigits int
		inpKey    []byte
		err       error
	}{
		{HOTP, crypto.SHA1, random.Intn(5) + 6, key, nil},
		{TOTP, crypto.SHA256, random.Intn(5) + 6, key, nil},
		{HOTP, crypto.SHA512, random.Intn(5) + 6, key, nil},
		{"", crypto.SHA512, 7, key, ErrUnknownAlgorithm},
		{TOTP, crypto.MD5, 7, key, ErrHashSupport},
		{HOTP, crypto.SHA1, 7, nil, ErrKeyLength},
		{TOTP, crypto.SHA256, 5, key, ErrDigitsRange},
		{HOTP, crypto.SHA512, 11, key, ErrDigitsRange},
	}

	for _, test := range tests {
		lTest := test

		t.Run(fmt.Sprintf("Can validate %+v", lTest), func(t *testing.T) {
			t.Parallel()

			otp := &OTP{
				Algorithm: lTest.inpAlg, Hash: lTest.inpHash, Key: lTest.inpKey,
				Digits: lTest.inpDigits,
			}

			err := otp.validate()
			t.Logf("err:%v", err)
			require.Equal(t, lTest.err, err)
		})
	}
}

func TestUri(t *testing.T) {
	t.Parallel()

	key, err := hex.DecodeString("b76c5da0d71b5646ed38b483532cded2622d072a5d1" +
		"75030b6540169b7380d58")
	require.NoError(t, err)

	b32Key := "W5WF3IGXDNLEN3JYWSBVGLG62JRC2BZKLULVAMFWKQAWTNZYBVMA"

	issuer := random.String(10)
	email := random.Email()

	tests := []struct {
		inpAlg     string
		inpHash    crypto.Hash
		inpDigits  int
		inpKey     []byte
		inpIssuer  string
		inpAccount string
		res        string
		err        error
	}{
		{
			HOTP, crypto.SHA1, 6, key, issuer, email, "otpauth://hotp/" +
				issuer + ":" + email + "?algorithm=SHA1&counter=0&digits=6" +
				"&issuer=" + issuer + "&secret=" + b32Key, nil,
		},
		{
			TOTP, crypto.SHA256, 7, key, issuer, email, "otpauth://totp/" +
				issuer + ":" + email + "?algorithm=SHA256&digits=7&issuer=" +
				issuer + "&period=30&secret=" + b32Key, nil,
		},
		{
			HOTP, crypto.SHA512, 8, key, "Company ABC", email,
			"otpauth://hotp/Company%20ABC:" + email + "?algorithm=SHA512&" +
				"counter=0&digits=8&issuer=Company%20ABC&secret=" + b32Key, nil,
		},
		{
			TOTP, crypto.SHA512, 7, nil, "", "", "", ErrKeyLength,
		},
	}

	for _, test := range tests {
		lTest := test

		t.Run(fmt.Sprintf("Can generate %+v", lTest), func(t *testing.T) {
			t.Parallel()

			otp := &OTP{
				Algorithm: lTest.inpAlg, Hash: lTest.inpHash, Key: lTest.inpKey,
				Digits: lTest.inpDigits, AccountName: lTest.inpAccount,
			}

			res, err := otp.uri(lTest.inpIssuer)
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
	email := random.Email()

	tests := []struct {
		inpAlg     string
		inpHash    crypto.Hash
		inpDigits  int
		inpKey     []byte
		inpIssuer  string
		inpAccount string
		err        error
	}{
		{HOTP, crypto.SHA1, 6, key, issuer, email, nil},
		{TOTP, crypto.SHA256, 7, key, issuer, email, nil},
		{HOTP, crypto.SHA512, 8, key, "Company ABC", email, nil},
		{HOTP, crypto.SHA512, 8, key, "Company ABC", "", nil},
		{TOTP, crypto.SHA512, 7, nil, "", "", ErrKeyLength},
	}

	for _, test := range tests {
		lTest := test

		t.Run(fmt.Sprintf("Can generate %+v", lTest), func(t *testing.T) {
			t.Parallel()

			otp := &OTP{
				Algorithm: lTest.inpAlg, Hash: lTest.inpHash, Key: lTest.inpKey,
				Digits: lTest.inpDigits, AccountName: lTest.inpAccount,
			}

			res, err := otp.QR(lTest.inpIssuer)
			t.Logf("res, err: %x, %v", res, err)
			if lTest.err == nil {
				require.Greater(t, len(res), 800)
			}
			require.Equal(t, lTest.err, err)
		})
	}
}
