// Package oath provides functions to generate and verify OATH one-time
// passwords (OTP).
package oath

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"math"
)

// DefaultHOTPLookAhead defines the default HOTP look-ahead count.
const DefaultHOTPLookAhead = 50

// HOTP generates a passcode using a counter.
func (o *OTP) HOTP(counter int64) (string, error) {
	if err := o.validate(); err != nil {
		return "", err
	}

	hash := hmac.New(o.Hash.New, o.Key)
	if err := binary.Write(hash, binary.BigEndian, counter); err != nil {
		return "", err
	}
	sum := hash.Sum(nil)

	offset := sum[hash.Size()-1] & 0x0f
	val := binary.BigEndian.Uint32(sum[offset:]) & 0x7fffffff
	mod := val % uint32(math.Pow10(o.Digits))

	return fmt.Sprintf("%0*d", o.Digits, mod), nil
}

// VerifyHOTP verifies a passcode using a look-ahead count and the current
// counter, and returns the next valid counter on success. lookAhead should
// usually be set to DefaultHOTPLookAhead for non-activation use cases.
func (o *OTP) VerifyHOTP(lookAhead int, counter int64, passcode string) (
	int64, error,
) {
	for i := range lookAhead {
		pass, err := o.HOTP(counter + int64(i))
		if err != nil {
			return 0, err
		}

		if hmac.Equal([]byte(pass), []byte(passcode)) {
			return counter + int64(i) + 1, nil
		}
	}

	return 0, ErrInvalidPasscode
}
