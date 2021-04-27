package identity

import (
	"crypto"
	"crypto/rand"

	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/hermes/pkg/oath"
)

const (
	defaultDigits = 7
	algHOTP       = "hotp"
	algTOTP       = "totp"
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

// methodToOTP converts an Identity MethodOneof into an algorithm, OTP, and bool
// representing whether the OTP secret and QR should be returned.
func methodToOTP(identity *api.Identity) (string, *oath.OTP, bool, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", nil, false, err
	}

	alg := algHOTP
	otp := &oath.OTP{Key: secret}
	retSecret := true

	switch m := identity.MethodOneof.(type) {
	case *api.Identity_SoftwareHotpMethod:
		otp.Hash = hashAPIToCrypto[m.SoftwareHotpMethod.Hash]

		if m.SoftwareHotpMethod.Digits == 0 {
			m.SoftwareHotpMethod.Digits = defaultDigits
		}
		otp.Digits = int(m.SoftwareHotpMethod.Digits)
	case *api.Identity_SoftwareTotpMethod:
		alg = algTOTP
		otp.Hash = hashAPIToCrypto[m.SoftwareTotpMethod.Hash]

		if m.SoftwareTotpMethod.Digits == 0 {
			m.SoftwareTotpMethod.Digits = defaultDigits
		}
		otp.Digits = int(m.SoftwareTotpMethod.Digits)
	case *api.Identity_GoogleAuthHotpMethod:
		otp.Hash = crypto.SHA512
		otp.Digits = defaultDigits
	case *api.Identity_GoogleAuthTotpMethod:
		alg = algTOTP
		otp.Hash = crypto.SHA512
		otp.Digits = defaultDigits
	case *api.Identity_MicrosoftAuthTotpMethod:
		alg = algTOTP
		otp.Hash = crypto.SHA1
		otp.Digits = 6
	case *api.Identity_HardwareHotpMethod:
		otp.Hash = hashAPIToCrypto[m.HardwareHotpMethod.Hash]
		otp.Digits = int(m.HardwareHotpMethod.Digits)

		otp.Key = m.HardwareHotpMethod.Secret
		m.HardwareHotpMethod.Secret = nil

		retSecret = false
	case *api.Identity_HardwareTotpMethod:
		alg = algTOTP
		otp.Hash = hashAPIToCrypto[m.HardwareTotpMethod.Hash]
		otp.Digits = int(m.HardwareTotpMethod.Digits)

		otp.Key = m.HardwareTotpMethod.Secret
		m.HardwareTotpMethod.Secret = nil

		retSecret = false
	}

	return alg, otp, retSecret, nil
}

// otpToMethod modifies an Identity MethodOneof in-place based on an algorithm,
// api.Hash, and digits.
func otpToMethod(identity *api.Identity, alg string, hash api.Hash,
	digits int32) {
	switch {
	case alg == algHOTP && hash == api.Hash_SHA512 && digits == defaultDigits:
		identity.MethodOneof = &api.Identity_GoogleAuthHotpMethod{
			GoogleAuthHotpMethod: &api.GoogleAuthHOTPMethod{},
		}
	case alg == algTOTP && hash == api.Hash_SHA512 && digits == defaultDigits:
		identity.MethodOneof = &api.Identity_GoogleAuthTotpMethod{
			GoogleAuthTotpMethod: &api.GoogleAuthTOTPMethod{},
		}
	case alg == algTOTP && hash == api.Hash_SHA1 && digits == 6:
		identity.MethodOneof = &api.Identity_MicrosoftAuthTotpMethod{
			MicrosoftAuthTotpMethod: &api.MicrosoftAuthTOTPMethod{},
		}
	case alg == algHOTP:
		identity.MethodOneof = &api.Identity_SoftwareHotpMethod{
			SoftwareHotpMethod: &api.SoftwareHOTPMethod{
				Hash: hash, Digits: digits,
			},
		}
	case alg == algTOTP:
		identity.MethodOneof = &api.Identity_SoftwareTotpMethod{
			SoftwareTotpMethod: &api.SoftwareTOTPMethod{
				Hash: hash, Digits: digits,
			},
		}
	}
}
