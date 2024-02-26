//go:build !integration

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
		inpDigits int
		inpKey    []byte
		inpTime   time.Time
		resDigits int
		resCode   string
		err       error
	}{
		{crypto.SHA1, 6, knownKey, knownTime, 6, "660634", nil},
		{crypto.SHA256, 7, knownKey, knownTime, 7, "2596747", nil},
		{crypto.SHA1, 6, randKey, time.Now(), 6, "", nil},
		{crypto.SHA256, 7, randKey, time.Now(), 7, "", nil},
		{crypto.SHA512, 8, randKey, time.Now(), 8, "", nil},
		{crypto.SHA512, 7, nil, time.Now(), 0, "", ErrKeyLength},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Can generate %+v", test), func(t *testing.T) {
			t.Parallel()

			otp := &OTP{
				Algorithm: TOTP, Hash: test.inpHash, Key: test.inpKey,
				Digits: test.inpDigits,
			}

			res, err := otp.TOTP(test.inpTime)
			t.Logf("res, err: %v, %v", res, err)
			require.Len(t, res, test.resDigits)
			if test.resCode != "" {
				require.Equal(t, test.resCode, res)
			}
			require.Equal(t, test.err, err)

			res, err = otp.TOTP(time.Now())
			t.Logf("res, err: %v, %v", res, err)
			require.Len(t, res, test.resDigits)
			require.Equal(t, test.err, err)
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
		inpDigits int
		inpKey    []byte
		inpOffset int
		inpTime   time.Time
		inpCode   string
		res       int
		err       error
	}{
		{crypto.SHA1, 6, key, 0, knownTime, "660634", 0, nil},
		{crypto.SHA256, 7, key, 0, knownTime, "2596747", 0, nil},
		{crypto.SHA512, 8, key, 0, knownTime, "76879241", 1, nil},
		{crypto.SHA512, 8, key, 2, knownTime, "76879241", 1, nil},
		{crypto.SHA512, 6, nil, 0, time.Now(), "000000", 0, ErrKeyLength},
		{crypto.SHA1, 6, key, 0, time.Now(), "000000", 0, ErrInvalidPasscode},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Can generate %+v", test), func(t *testing.T) {
			t.Parallel()

			otp := &OTP{
				Algorithm: TOTP, Hash: test.inpHash, Key: test.inpKey,
				Digits: test.inpDigits,
			}

			res, err := otp.verifyTOTP(DefaultTOTPLookAhead, test.inpOffset,
				test.inpTime, test.inpCode)
			t.Logf("res, err: %v, %v", res, err)
			require.Equal(t, test.res, res)
			require.Equal(t, test.err, err)

			if test.err == nil {
				code, err := otp.TOTP(time.Now().Add(time.Duration(
					test.res*period) * time.Second))
				t.Logf("code, err: %v, %v", code, err)
				require.NoError(t, err)

				res, err = otp.VerifyTOTP(DefaultTOTPLookAhead, test.inpOffset,
					code)
				t.Logf("res, err: %v, %v", res, err)
				require.Equal(t, test.res, res)
				require.NoError(t, err)
			}
		})
	}
}
