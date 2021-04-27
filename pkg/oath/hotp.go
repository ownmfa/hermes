// Package oath provides functions to generate and verify OATH one-time
// passwords (OTP).
package oath

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"math"
)

const lookAhead = 100

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

// VerifyHOTP verifies a passcode using the current counter and a look-ahead
// window. On success, the next valid counter is returned.
func (o *OTP) VerifyHOTP(counter int64, passcode string) (int64, error) {
	var i int64
	for i = 0; i < lookAhead; i++ {
		pass, err := o.HOTP(counter + i)
		if err != nil {
			return 0, err
		}

		if hmac.Equal([]byte(pass), []byte(passcode)) {
			return counter + i + 1, nil
		}
	}

	return 0, ErrInvalidPasscode
}
