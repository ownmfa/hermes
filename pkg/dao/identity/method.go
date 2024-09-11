package identity

import (
	"crypto"
	"crypto/rand"
	"strings"

	"github.com/ownmfa/hermes/pkg/consterr"
	"github.com/ownmfa/hermes/pkg/oath"
	"github.com/ownmfa/proto/go/api"
)

const (
	defaultDigits = 7
	defaultAnswer = "********"

	errUnknownMethodOneof consterr.Error = "unknown identity.MethodOneof"
)

// otpMeta represents OTP metadata.
type otpMeta struct {
	phone       string
	pushoverKey string
	email       string
	backupCodes int32

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

	switch m := identity.GetMethodOneof().(type) {
	case *api.Identity_SoftwareHotpMethod:
		otp.Hash = hashAPIToCrypto[m.SoftwareHotpMethod.GetHash()]
		otp.AccountName = m.SoftwareHotpMethod.GetAccountName()

		if m.SoftwareHotpMethod.GetDigits() == 0 {
			m.SoftwareHotpMethod.Digits = defaultDigits
		}
		otp.Digits = int(m.SoftwareHotpMethod.GetDigits())
	case *api.Identity_SoftwareTotpMethod:
		otp.Algorithm = oath.TOTP
		otp.Hash = hashAPIToCrypto[m.SoftwareTotpMethod.GetHash()]
		otp.AccountName = m.SoftwareTotpMethod.GetAccountName()

		if m.SoftwareTotpMethod.GetDigits() == 0 {
			m.SoftwareTotpMethod.Digits = defaultDigits
		}
		otp.Digits = int(m.SoftwareTotpMethod.GetDigits())
	case *api.Identity_GoogleAuthHotpMethod:
		otp.Hash = crypto.SHA1
		otp.Digits = 6
		otp.AccountName = m.GoogleAuthHotpMethod.GetAccountName()
	case *api.Identity_GoogleAuthTotpMethod:
		otp.Algorithm = oath.TOTP
		otp.Hash = crypto.SHA1
		otp.Digits = 6
		otp.AccountName = m.GoogleAuthTotpMethod.GetAccountName()
	case *api.Identity_AppleIosTotpMethod:
		otp.Algorithm = oath.TOTP
		otp.Hash = crypto.SHA512
		otp.Digits = defaultDigits
	case *api.Identity_HardwareHotpMethod:
		otp.Hash = hashAPIToCrypto[m.HardwareHotpMethod.GetHash()]
		otp.Digits = int(m.HardwareHotpMethod.GetDigits())

		otp.Key = m.HardwareHotpMethod.GetSecret()
		m.HardwareHotpMethod.Secret = nil

		meta.retSecret = false
	case *api.Identity_HardwareTotpMethod:
		otp.Algorithm = oath.TOTP
		otp.Hash = hashAPIToCrypto[m.HardwareTotpMethod.GetHash()]
		otp.Digits = int(m.HardwareTotpMethod.GetDigits())

		otp.Key = m.HardwareTotpMethod.GetSecret()
		m.HardwareTotpMethod.Secret = nil

		meta.retSecret = false
	case *api.Identity_SmsMethod:
		otp.Hash = crypto.SHA512
		otp.Digits = defaultDigits

		meta.phone = m.SmsMethod.GetPhone()
		meta.retSecret = false
	case *api.Identity_PushoverMethod:
		otp.Hash = crypto.SHA512
		otp.Digits = defaultDigits

		meta.pushoverKey = m.PushoverMethod.GetPushoverKey()
		meta.retSecret = false
	case *api.Identity_EmailMethod:
		otp.Hash = crypto.SHA512
		otp.Digits = defaultDigits

		meta.email = m.EmailMethod.GetEmail()
		meta.retSecret = false
	case *api.Identity_BackupCodesMethod:
		otp.Hash = crypto.SHA512
		otp.Digits = defaultDigits

		meta.backupCodes = m.BackupCodesMethod.GetPasscodes()
		meta.retSecret = false
	case *api.Identity_SecurityQuestionsMethod:
		otp.Hash = crypto.SHA512
		otp.Digits = defaultDigits

		otp.Answer = strings.ToLower(m.SecurityQuestionsMethod.GetAnswer())
		m.SecurityQuestionsMethod.Answer = defaultAnswer

		meta.retSecret = false
	default:
		return nil, nil, errUnknownMethodOneof
	}

	return otp, meta, nil
}

// otpToMethod modifies an Identity MethodOneof in-place based on an OTP and
// otpMeta. Identity MethodOneof may be returned in simplified form.
func otpToMethod(identity *api.Identity, otp *oath.OTP, meta *otpMeta) {
	switch {
	case otp.Answer != "":
		identity.MethodOneof = &api.Identity_SecurityQuestionsMethod{
			SecurityQuestionsMethod: &api.SecurityQuestionsMethod{
				Answer: defaultAnswer,
			},
		}
	case meta.backupCodes > 0:
		identity.MethodOneof = &api.Identity_BackupCodesMethod{
			BackupCodesMethod: &api.BackupsCodesMethod{
				Passcodes: meta.backupCodes,
			},
		}
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
	case otp.Algorithm == oath.TOTP && otp.Hash == crypto.SHA512 &&
		otp.Digits == defaultDigits:
		identity.MethodOneof = &api.Identity_AppleIosTotpMethod{
			AppleIosTotpMethod: &api.AppleiOSTOTPMethod{},
		}
	case otp.Algorithm == oath.HOTP:
		//nolint:gosec // Safe conversion for limited values.
		identity.MethodOneof = &api.Identity_SoftwareHotpMethod{
			SoftwareHotpMethod: &api.SoftwareHOTPMethod{
				Hash: hashCryptoToAPI[otp.Hash], Digits: int32(otp.Digits),
			},
		}
	case otp.Algorithm == oath.TOTP:
		//nolint:gosec // Safe conversion for limited values.
		identity.MethodOneof = &api.Identity_SoftwareTotpMethod{
			SoftwareTotpMethod: &api.SoftwareTOTPMethod{
				Hash: hashCryptoToAPI[otp.Hash], Digits: int32(otp.Digits),
			},
		}
	}
}
