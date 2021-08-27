//go:build !integration

package oath

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/stretchr/testify/require"
)

func TestHOTP(t *testing.T) {
	t.Parallel()

	knownKey, err := hex.DecodeString("b76c5da0d71b5646ed38b483532cded2622d07" +
		"2a5d175030b6540169b7380d58")
	require.NoError(t, err)

	randKey := make([]byte, 32)
	_, err = rand.Read(randKey)
	require.NoError(t, err)

	tests := []struct {
		inpHash    crypto.Hash
		inpDigits  int
		inpKey     []byte
		inpCounter int64
		resDigits  int
		resCode    string
		err        error
	}{
		{crypto.SHA1, 6, knownKey, int64(5), 6, "861821", nil},
		{crypto.SHA256, 7, knownKey, int64(1), 7, "1915540", nil},
		{crypto.SHA1, 6, randKey, int64(random.Intn(99)), 6, "", nil},
		{crypto.SHA256, 7, randKey, int64(random.Intn(99)), 7, "", nil},
		{crypto.SHA512, 8, randKey, int64(random.Intn(99)), 8, "", nil},
		{crypto.SHA512, 7, nil, 0, 0, "", ErrKeyLength},
	}

	for _, test := range tests {
		lTest := test

		t.Run(fmt.Sprintf("Can generate %+v", lTest), func(t *testing.T) {
			t.Parallel()

			otp := &OTP{
				Algorithm: HOTP, Hash: lTest.inpHash, Key: lTest.inpKey,
				Digits: lTest.inpDigits,
			}

			res, err := otp.HOTP(lTest.inpCounter)
			t.Logf("res, err: %v, %v", res, err)
			require.Len(t, res, lTest.resDigits)
			if lTest.resCode != "" {
				require.Equal(t, lTest.resCode, res)
			}
			require.Equal(t, lTest.err, err)
		})
	}
}

func TestVerifyHOTP(t *testing.T) {
	t.Parallel()

	key, err := hex.DecodeString("b76c5da0d71b5646ed38b483532cded2622d072a5d1" +
		"75030b6540169b7380d58")
	require.NoError(t, err)

	tests := []struct {
		inpHash   crypto.Hash
		inpDigits int
		inpKey    []byte
		inpCode   string
		res       int64
		err       error
	}{
		{crypto.SHA1, 6, key, "861821", 6, nil},
		{crypto.SHA256, 7, key, "1915540", 2, nil},
		{crypto.SHA1, 6, key, "244449", 50, nil},
		{crypto.SHA512, 6, nil, "000000", 0, ErrKeyLength},
		{crypto.SHA1, 6, key, "000000", 0, ErrInvalidPasscode},
	}

	for _, test := range tests {
		lTest := test

		t.Run(fmt.Sprintf("Can generate %+v", lTest), func(t *testing.T) {
			t.Parallel()

			otp := &OTP{
				Algorithm: HOTP, Hash: lTest.inpHash, Key: lTest.inpKey,
				Digits: lTest.inpDigits,
			}

			res, err := otp.VerifyHOTP(DefaultHOTPLookAhead, 0, lTest.inpCode)
			t.Logf("res, err: %v, %v", res, err)
			require.Equal(t, lTest.res, res)
			require.Equal(t, lTest.err, err)
		})
	}
}
