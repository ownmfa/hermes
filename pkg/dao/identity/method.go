package identity

import (
	"crypto"
	"crypto/rand"

	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/hermes/pkg/consterr"
	"github.com/ownmfa/hermes/pkg/oath"
)

const (
	defaultDigits = 7

	errUnknownMethodOneof consterr.Error = "unknown identity.MethodOneof"
)

// hashAPIToCrypto maps an api.Hash to a crypto.Hash.
var hashAPIToCrypto = map[api.Hash]crypto.Hash{
	api.Hash_SHA512: crypto.SHA512,
	api.Hash_SHA256: crypto.SHA256,
	api.Hash_SHA1:   crypto.SHA1,
}

// hashCryptoToAPI maps a crypto.Hash to an api.Hash.
var hashCryptoToAPI = map[crypto.Hash]api.Hash{
	crypto.SHA512: api.Hash_SHA512,
	crypto.SHA256: api.Hash_SHA256,
	crypto.SHA1:   api.Hash_SHA1,
}

// methodToOTP converts an Identity MethodOneof into an OTP, phone number, and
// bool representing whether the OTP secret and QR should be returned.
func methodToOTP(identity *api.Identity) (*oath.OTP, string, bool, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, "", false, err
	}

	otp := &oath.OTP{Algorithm: oath.HOTP, Key: secret}
	var phone string
	retSecret := true

	switch m := identity.MethodOneof.(type) {
	case *api.Identity_SoftwareHotpMethod:
		otp.Hash = hashAPIToCrypto[m.SoftwareHotpMethod.Hash]
		otp.AccountName = m.SoftwareHotpMethod.AccountName

		if m.SoftwareHotpMethod.Digits == 0 {
			m.SoftwareHotpMethod.Digits = defaultDigits
		}
		otp.Digits = int(m.SoftwareHotpMethod.Digits)
	case *api.Identity_SoftwareTotpMethod:
		otp.Algorithm = oath.TOTP
		otp.Hash = hashAPIToCrypto[m.SoftwareTotpMethod.Hash]
		otp.AccountName = m.SoftwareTotpMethod.AccountName

		if m.SoftwareTotpMethod.Digits == 0 {
			m.SoftwareTotpMethod.Digits = defaultDigits
		}
		otp.Digits = int(m.SoftwareTotpMethod.Digits)
	case *api.Identity_GoogleAuthHotpMethod:
		otp.Hash = crypto.SHA512
		otp.Digits = defaultDigits
		otp.AccountName = m.GoogleAuthHotpMethod.AccountName
	case *api.Identity_GoogleAuthTotpMethod:
		otp.Algorithm = oath.TOTP
		otp.Hash = crypto.SHA512
		otp.Digits = defaultDigits
		otp.AccountName = m.GoogleAuthTotpMethod.AccountName
	case *api.Identity_MicrosoftAuthTotpMethod:
		otp.Algorithm = oath.TOTP
		otp.Hash = crypto.SHA1
		otp.Digits = 6
		otp.AccountName = m.MicrosoftAuthTotpMethod.AccountName
	case *api.Identity_HardwareHotpMethod:
		otp.Hash = hashAPIToCrypto[m.HardwareHotpMethod.Hash]
		otp.Digits = int(m.HardwareHotpMethod.Digits)

		otp.Key = m.HardwareHotpMethod.Secret
		m.HardwareHotpMethod.Secret = nil

		retSecret = false
	case *api.Identity_HardwareTotpMethod:
		otp.Algorithm = oath.TOTP
		otp.Hash = hashAPIToCrypto[m.HardwareTotpMethod.Hash]
		otp.Digits = int(m.HardwareTotpMethod.Digits)

		otp.Key = m.HardwareTotpMethod.Secret
		m.HardwareTotpMethod.Secret = nil

		retSecret = false
	case *api.Identity_SmsMethod:
		otp.Hash = crypto.SHA512
		otp.Digits = defaultDigits

		phone = m.SmsMethod.Phone
		retSecret = false
	default:
		return nil, "", false, errUnknownMethodOneof
	}

	return otp, phone, retSecret, nil
}

// otpToMethod modifies an Identity MethodOneof in-place based on a phone
// number, algorithm, api.Hash, and digits.
func otpToMethod(identity *api.Identity, phone, algorithm string, hash api.Hash,
	digits int32) {
	switch {
	case phone != "":
		identity.MethodOneof = &api.Identity_SmsMethod{
			SmsMethod: &api.SMSMethod{Phone: phone},
		}
	case algorithm == oath.HOTP && hash == api.Hash_SHA512 &&
		digits == defaultDigits:
		identity.MethodOneof = &api.Identity_GoogleAuthHotpMethod{
			GoogleAuthHotpMethod: &api.GoogleAuthHOTPMethod{},
		}
	case algorithm == oath.TOTP && hash == api.Hash_SHA512 &&
		digits == defaultDigits:
		identity.MethodOneof = &api.Identity_GoogleAuthTotpMethod{
			GoogleAuthTotpMethod: &api.GoogleAuthTOTPMethod{},
		}
	case algorithm == oath.TOTP && hash == api.Hash_SHA1 && digits == 6:
		identity.MethodOneof = &api.Identity_MicrosoftAuthTotpMethod{
			MicrosoftAuthTotpMethod: &api.MicrosoftAuthTOTPMethod{},
		}
	case algorithm == oath.HOTP:
		identity.MethodOneof = &api.Identity_SoftwareHotpMethod{
			SoftwareHotpMethod: &api.SoftwareHOTPMethod{
				Hash: hash, Digits: digits,
			},
		}
	case algorithm == oath.TOTP:
		identity.MethodOneof = &api.Identity_SoftwareTotpMethod{
			SoftwareTotpMethod: &api.SoftwareTOTPMethod{
				Hash: hash, Digits: digits,
			},
		}
	}
}
