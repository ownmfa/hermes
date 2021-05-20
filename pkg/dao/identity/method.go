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

// otpMeta represents OTP metadata.
type otpMeta struct {
	phone       string
	pushoverKey string
	email       string

	// retSecret indicates whether the OTP secret and QR should be returned.
	retSecret bool
}

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

// methodToOTP converts an Identity MethodOneof into an OTP and otpMeta.
func methodToOTP(identity *api.Identity) (*oath.OTP, *otpMeta, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, nil, err
	}

	otp := &oath.OTP{Algorithm: oath.HOTP, Key: secret}
	meta := &otpMeta{retSecret: true}

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
		otp.Hash = crypto.SHA1
		otp.Digits = 6
		otp.AccountName = m.GoogleAuthHotpMethod.AccountName
	case *api.Identity_GoogleAuthTotpMethod:
		otp.Algorithm = oath.TOTP
		otp.Hash = crypto.SHA1
		otp.Digits = 6
		otp.AccountName = m.GoogleAuthTotpMethod.AccountName
	case *api.Identity_HardwareHotpMethod:
		otp.Hash = hashAPIToCrypto[m.HardwareHotpMethod.Hash]
		otp.Digits = int(m.HardwareHotpMethod.Digits)

		otp.Key = m.HardwareHotpMethod.Secret
		m.HardwareHotpMethod.Secret = nil

		meta.retSecret = false
	case *api.Identity_HardwareTotpMethod:
		otp.Algorithm = oath.TOTP
		otp.Hash = hashAPIToCrypto[m.HardwareTotpMethod.Hash]
		otp.Digits = int(m.HardwareTotpMethod.Digits)

		otp.Key = m.HardwareTotpMethod.Secret
		m.HardwareTotpMethod.Secret = nil

		meta.retSecret = false
	case *api.Identity_SmsMethod:
		otp.Hash = crypto.SHA512
		otp.Digits = defaultDigits

		meta.phone = m.SmsMethod.Phone
		meta.retSecret = false
	case *api.Identity_PushoverMethod:
		otp.Hash = crypto.SHA512
		otp.Digits = defaultDigits

		meta.pushoverKey = m.PushoverMethod.PushoverKey
		meta.retSecret = false
	case *api.Identity_EmailMethod:
		otp.Hash = crypto.SHA512
		otp.Digits = defaultDigits

		meta.email = m.EmailMethod.Email
		meta.retSecret = false
	default:
		return nil, nil, errUnknownMethodOneof
	}

	return otp, meta, nil
}

// otpToMethod modifies an Identity MethodOneof in-place based on an OTP and
// otpMeta.
func otpToMethod(identity *api.Identity, otp *oath.OTP, meta *otpMeta) {
	switch {
	case meta.email != "":
		identity.MethodOneof = &api.Identity_EmailMethod{
			EmailMethod: &api.EmailMethod{Email: meta.email},
		}
	case meta.pushoverKey != "":
		identity.MethodOneof = &api.Identity_PushoverMethod{
			PushoverMethod: &api.PushoverMethod{PushoverKey: meta.pushoverKey},
		}
	case meta.phone != "":
		identity.MethodOneof = &api.Identity_SmsMethod{
			SmsMethod: &api.SMSMethod{Phone: meta.phone},
		}
	case otp.Algorithm == oath.HOTP && otp.Hash == crypto.SHA1 &&
		otp.Digits == 6:
		identity.MethodOneof = &api.Identity_GoogleAuthHotpMethod{
			GoogleAuthHotpMethod: &api.GoogleAuthHOTPMethod{},
		}
	case otp.Algorithm == oath.TOTP && otp.Hash == crypto.SHA1 &&
		otp.Digits == 6:
		identity.MethodOneof = &api.Identity_GoogleAuthTotpMethod{
			GoogleAuthTotpMethod: &api.GoogleAuthTOTPMethod{},
		}
	case otp.Algorithm == oath.HOTP:
		identity.MethodOneof = &api.Identity_SoftwareHotpMethod{
			SoftwareHotpMethod: &api.SoftwareHOTPMethod{
				Hash: hashCryptoToAPI[otp.Hash], Digits: int32(otp.Digits),
			},
		}
	case otp.Algorithm == oath.TOTP:
		identity.MethodOneof = &api.Identity_SoftwareTotpMethod{
			SoftwareTotpMethod: &api.SoftwareTOTPMethod{
				Hash: hashCryptoToAPI[otp.Hash], Digits: int32(otp.Digits),
			},
		}
	}
}
