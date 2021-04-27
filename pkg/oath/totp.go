// Package oath provides functions to generate and verify OATH one-time
// passwords (OTP).
package oath

import (
	"crypto/hmac"
	"time"
)

// TOTP generates a passcode based on the current time.
func (o *OTP) TOTP() (string, error) {
	return o.totp(time.Now())
}

// totp generates a passcode based on the provided time.
func (o *OTP) totp(t time.Time) (string, error) {
	return o.HOTP(t.UnixNano() / int64(time.Duration(period)*time.Second))
}

// VerifyTOTP verifies a passcode using look-ahead and look-behind windows based
// on the current time.
func (o *OTP) VerifyTOTP(passcode string) error {
	return o.verifyTOTP(time.Now(), passcode)
}

// verifyTOTP verifies a passcode using look-ahead and look-behind windows based
// on the provided time.
func (o *OTP) verifyTOTP(t time.Time, passcode string) error {
	for _, d := range []int{0, -1, 1} {
		pass, err := o.totp(t.Add(time.Duration(d*period) * time.Second))
		if err != nil {
			return err
		}

		if hmac.Equal([]byte(pass), []byte(passcode)) {
			return nil
		}
	}

	return ErrInvalidPasscode
}
