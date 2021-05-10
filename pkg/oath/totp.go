// Package oath provides functions to generate and verify OATH one-time
// passwords (OTP).
package oath

import (
	"crypto/hmac"
	"time"
)

// DefaultTOTPLookAhead defines the default look-ahead window count.
const DefaultTOTPLookAhead = 1

// TOTP generates a passcode based on the provided time.
func (o *OTP) TOTP(t time.Time) (string, error) {
	return o.HOTP(t.UnixNano() / int64(time.Duration(period)*time.Second))
}

// VerifyTOTP verifies a passcode using look-ahead (and look-behind) window
// count and window offset, based on the current time, and returns the window
// offset on success. lookAhead should usually be set to DefaultTOTPLookAhead
// for non-activation use cases.
func (o *OTP) VerifyTOTP(lookAhead, offset int, passcode string) (int, error) {
	return o.verifyTOTP(lookAhead, offset, time.Now(), passcode)
}

// verifyTOTP verifies a passcode using look-ahead (and look-behind) window
// count and window offset, based on the provided time, and returns the window
// offset on success. lookAhead should usually be set to DefaultTOTPLookAhead
// for non-activation use cases.
func (o *OTP) verifyTOTP(lookAhead, offset int, t time.Time,
	passcode string) (int, error) {
	for i := -lookAhead + offset; i <= lookAhead+offset; i++ {
		pass, err := o.TOTP(t.Add(time.Duration(i*period) * time.Second))
		if err != nil {
			return 0, err
		}

		if hmac.Equal([]byte(pass), []byte(passcode)) {
			return i, nil
		}
	}

	return 0, ErrInvalidPasscode
}
