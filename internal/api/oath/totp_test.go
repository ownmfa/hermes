// +build !integration

package oath

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTOTP(t *testing.T) {
	t.Parallel()

	knownKey, err := hex.DecodeString("b76c5da0d71b5646ed38b483532cded2622d07" +
		"2a5d175030b6540169b7380d58")
	require.NoError(t, err)

	knownTime := time.Unix(1619184008, 0)

	randKey := make([]byte, 32)
	_, err = rand.Read(randKey)
	require.NoError(t, err)

	tests := []struct {
		inpHash   crypto.Hash
		inpKey    []byte
		inpDigits int
		inpTime   time.Time
		resDigits int
		resCode   string
		err       error
	}{
		{crypto.SHA1, knownKey, 6, knownTime, 6, "660634", nil},
		{crypto.SHA256, knownKey, 7, knownTime, 7, "2596747", nil},
		{crypto.SHA1, randKey, 6, time.Now(), 6, "", nil},
		{crypto.SHA256, randKey, 7, time.Now(), 7, "", nil},
		{crypto.SHA512, randKey, 8, time.Now(), 8, "", nil},
		{crypto.SHA512, randKey, 9, time.Now(), 7, "", nil},
		{crypto.SHA1, nil, 7, time.Now(), 0, "", ErrKeyLength},
	}

	for _, test := range tests {
		lTest := test

		t.Run(fmt.Sprintf("Can generate %+v", lTest), func(t *testing.T) {
			t.Parallel()

			otp := &OTP{
				Hash: lTest.inpHash, Key: lTest.inpKey, Digits: lTest.inpDigits,
			}

			res, err := otp.totp(lTest.inpTime)
			t.Logf("res, err: %v, %v", res, err)
			require.Len(t, res, lTest.resDigits)
			if lTest.resCode != "" {
				require.Equal(t, lTest.resCode, res)
			}
			require.Equal(t, lTest.err, err)

			res, err = otp.TOTP()
			t.Logf("res, err: %v, %v", res, err)
			require.Len(t, res, lTest.resDigits)
			require.Equal(t, lTest.err, err)
		})
	}
}

func TestVerifyTOTP(t *testing.T) {
	t.Parallel()

	key, err := hex.DecodeString("b76c5da0d71b5646ed38b483532cded2622d072a5d1" +
		"75030b6540169b7380d58")
	require.NoError(t, err)

	knownTime := time.Unix(1619184008, 0)

	tests := []struct {
		inpHash   crypto.Hash
		inpKey    []byte
		inpDigits int
		inpTime   time.Time
		inpCode   string
		err       error
	}{
		{crypto.SHA1, key, 6, knownTime, "660634", nil},
		{crypto.SHA256, key, 7, knownTime, "2596747", nil},
		{crypto.SHA512, key, 8, knownTime, "76879241", nil},
		{crypto.SHA1, nil, 6, time.Now(), "000000", ErrKeyLength},
		{crypto.SHA1, key, 6, time.Now(), "000000", ErrInvalidPasscode},
	}

	for _, test := range tests {
		lTest := test

		t.Run(fmt.Sprintf("Can generate %+v", lTest), func(t *testing.T) {
			t.Parallel()

			otp := &OTP{
				Hash: lTest.inpHash, Key: lTest.inpKey, Digits: lTest.inpDigits,
			}

			err := otp.verifyTOTP(lTest.inpTime, lTest.inpCode)
			t.Logf("err: %v", err)
			require.Equal(t, lTest.err, err)

			if lTest.err == nil {
				res, err := otp.TOTP()
				t.Logf("res, err: %v, %v", res, err)
				require.NoError(t, err)

				require.NoError(t, otp.VerifyTOTP(res))
			}
		})
	}
}
