//go:build !integration

package identity

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/hermes/pkg/oath"
	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestMethodToOTP(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	email := random.Email()
	phone := random.String(10)
	pushoverKey := random.String(10)
	backupCodes := int32(random.Intn(5) + 6)
	answer := random.String(80)

	tests := []struct {
		inp     *api.Identity
		resOTP  *oath.OTP
		resMeta *otpMeta
		err     error
	}{
		{
			&api.Identity{MethodOneof: &api.Identity_SoftwareHotpMethod{
				SoftwareHotpMethod: &api.SoftwareHOTPMethod{AccountName: email},
			}}, &oath.OTP{
				Algorithm: oath.HOTP, Hash: crypto.SHA512,
				Digits: defaultDigits, AccountName: email,
			}, &otpMeta{retSecret: true}, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_SoftwareTotpMethod{
				SoftwareTotpMethod: &api.SoftwareTOTPMethod{},
			}}, &oath.OTP{
				Algorithm: oath.TOTP, Hash: crypto.SHA512,
				Digits: defaultDigits,
			}, &otpMeta{retSecret: true}, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_GoogleAuthHotpMethod{
				GoogleAuthHotpMethod: &api.GoogleAuthHOTPMethod{},
			}}, &oath.OTP{
				Algorithm: oath.HOTP, Hash: crypto.SHA1, Digits: 6,
			}, &otpMeta{retSecret: true}, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_GoogleAuthTotpMethod{
				GoogleAuthTotpMethod: &api.GoogleAuthTOTPMethod{
					AccountName: email,
				},
			}}, &oath.OTP{
				Algorithm: oath.TOTP, Hash: crypto.SHA1, Digits: 6,
				AccountName: email,
			}, &otpMeta{retSecret: true}, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_AppleIosTotpMethod{
				AppleIosTotpMethod: &api.AppleiOSTOTPMethod{},
			}}, &oath.OTP{
				Algorithm: oath.TOTP, Hash: crypto.SHA512,
				Digits: defaultDigits,
			}, &otpMeta{retSecret: true}, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_HardwareHotpMethod{
				HardwareHotpMethod: &api.HardwareHOTPMethod{
					Digits: 8, Secret: key,
				},
			}}, &oath.OTP{
				Algorithm: oath.HOTP, Hash: crypto.SHA512, Digits: 8,
			}, &otpMeta{}, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_HardwareTotpMethod{
				HardwareTotpMethod: &api.HardwareTOTPMethod{
					Digits: 9, Secret: key,
				},
			}}, &oath.OTP{
				Algorithm: oath.TOTP, Hash: crypto.SHA512, Digits: 9,
			}, &otpMeta{}, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_SmsMethod{
				SmsMethod: &api.SMSMethod{Phone: phone},
			}}, &oath.OTP{
				Algorithm: oath.HOTP, Hash: crypto.SHA512,
				Digits: defaultDigits,
			}, &otpMeta{phone: phone}, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_PushoverMethod{
				PushoverMethod: &api.PushoverMethod{
					PushoverKey: pushoverKey,
				},
			}}, &oath.OTP{
				Algorithm: oath.HOTP, Hash: crypto.SHA512,
				Digits: defaultDigits,
			}, &otpMeta{pushoverKey: pushoverKey}, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_EmailMethod{
				EmailMethod: &api.EmailMethod{Email: email},
			}}, &oath.OTP{
				Algorithm: oath.HOTP, Hash: crypto.SHA512,
				Digits: defaultDigits,
			}, &otpMeta{email: email}, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_BackupCodesMethod{
				BackupCodesMethod: &api.BackupsCodesMethod{
					Passcodes: backupCodes,
				},
			}}, &oath.OTP{
				Algorithm: oath.HOTP, Hash: crypto.SHA512,
				Digits: defaultDigits,
			}, &otpMeta{backupCodes: backupCodes}, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_SecurityQuestionsMethod{
				SecurityQuestionsMethod: &api.SecurityQuestionsMethod{
					Answer: strings.ToUpper(answer),
				},
			}}, &oath.OTP{
				Algorithm: oath.HOTP, Hash: crypto.SHA512,
				Digits: defaultDigits, Answer: answer,
			}, &otpMeta{}, nil,
		},
		{
			&api.Identity{MethodOneof: nil}, nil, nil, errUnknownMethodOneof,
		},
	}

	for _, test := range tests {
		lTest := test

		t.Run(fmt.Sprintf("Can convert %+v", lTest), func(t *testing.T) {
			t.Parallel()

			identity := random.HOTPIdentity("dao-identity", uuid.NewString(),
				uuid.NewString())
			identity.MethodOneof = lTest.inp.MethodOneof

			otp, meta, err := methodToOTP(identity)
			t.Logf("otp, meta, err: %#v, %#v, %v", otp, meta, err)

			// Normalize secret.
			if lTest.resOTP != nil {
				require.Len(t, otp.Key, 32)
				lTest.resOTP.Key = otp.Key
			}

			require.Equal(t, lTest.resOTP, otp)
			require.Equal(t, lTest.resMeta, meta)
			require.Equal(t, lTest.err, err)
		})
	}
}

func TestOTPToMethod(t *testing.T) {
	t.Parallel()

	answer := random.String(80)
	backupCodes := int32(random.Intn(5) + 6)
	email := random.Email()
	pushoverKey := random.String(30)
	phone := random.String(10)

	tests := []struct {
		inpOTP  *oath.OTP
		inpMeta *otpMeta
		res     *api.Identity
	}{
		{
			&oath.OTP{
				Algorithm: oath.HOTP, Hash: crypto.SHA512,
				Digits: defaultDigits, Answer: answer,
			}, &otpMeta{}, &api.Identity{
				MethodOneof: &api.Identity_SecurityQuestionsMethod{
					SecurityQuestionsMethod: &api.SecurityQuestionsMethod{
						Answer: defaultAnswer,
					},
				},
			},
		},
		{
			&oath.OTP{
				Algorithm: oath.HOTP, Hash: crypto.SHA512,
				Digits: defaultDigits,
			}, &otpMeta{backupCodes: backupCodes}, &api.Identity{
				MethodOneof: &api.Identity_BackupCodesMethod{
					BackupCodesMethod: &api.BackupsCodesMethod{
						Passcodes: backupCodes,
					},
				},
			},
		},
		{
			&oath.OTP{
				Algorithm: oath.HOTP, Hash: crypto.SHA512,
				Digits: defaultDigits,
			}, &otpMeta{email: email}, &api.Identity{
				MethodOneof: &api.Identity_EmailMethod{
					EmailMethod: &api.EmailMethod{Email: email},
				},
			},
		},
		{
			&oath.OTP{
				Algorithm: oath.HOTP, Hash: crypto.SHA512,
				Digits: defaultDigits,
			}, &otpMeta{pushoverKey: pushoverKey}, &api.Identity{
				MethodOneof: &api.Identity_PushoverMethod{
					PushoverMethod: &api.PushoverMethod{
						PushoverKey: pushoverKey,
					},
				},
			},
		},
		{
			&oath.OTP{
				Algorithm: oath.HOTP, Hash: crypto.SHA512,
				Digits: defaultDigits,
			}, &otpMeta{phone: phone}, &api.Identity{
				MethodOneof: &api.Identity_SmsMethod{
					SmsMethod: &api.SMSMethod{Phone: phone},
				},
			},
		},
		{
			&oath.OTP{Algorithm: oath.HOTP, Hash: crypto.SHA1, Digits: 6},
			&otpMeta{}, &api.Identity{
				MethodOneof: &api.Identity_GoogleAuthHotpMethod{
					GoogleAuthHotpMethod: &api.GoogleAuthHOTPMethod{},
				},
			},
		},
		{
			&oath.OTP{Algorithm: oath.TOTP, Hash: crypto.SHA1, Digits: 6},
			&otpMeta{}, &api.Identity{
				MethodOneof: &api.Identity_GoogleAuthTotpMethod{
					GoogleAuthTotpMethod: &api.GoogleAuthTOTPMethod{},
				},
			},
		},
		{
			&oath.OTP{
				Algorithm: oath.TOTP, Hash: crypto.SHA512,
				Digits: defaultDigits,
			}, &otpMeta{}, &api.Identity{
				MethodOneof: &api.Identity_AppleIosTotpMethod{
					AppleIosTotpMethod: &api.AppleiOSTOTPMethod{},
				},
			},
		},
		{
			&oath.OTP{Algorithm: oath.HOTP, Hash: crypto.SHA512, Digits: 8},
			&otpMeta{}, &api.Identity{
				MethodOneof: &api.Identity_SoftwareHotpMethod{
					SoftwareHotpMethod: &api.SoftwareHOTPMethod{
						Hash: api.Hash_SHA512, Digits: 8,
					},
				},
			},
		},
		{
			&oath.OTP{Algorithm: oath.TOTP, Hash: crypto.SHA256, Digits: 9},
			&otpMeta{}, &api.Identity{
				MethodOneof: &api.Identity_SoftwareTotpMethod{
					SoftwareTotpMethod: &api.SoftwareTOTPMethod{
						Hash: api.Hash_SHA256, Digits: 9,
					},
				},
			},
		},
	}

	for _, test := range tests {
		lTest := test

		t.Run(fmt.Sprintf("Can modify %+v", lTest), func(t *testing.T) {
			t.Parallel()

			identity := &api.Identity{}
			otpToMethod(identity, lTest.inpOTP, lTest.inpMeta)
			t.Logf("identity: %+v", identity)

			// Testify does not currently support protobuf equality:
			// https://github.com/stretchr/testify/issues/758
			if !proto.Equal(lTest.res, identity) {
				t.Fatalf("\nExpect: %+v\nActual: %+v", lTest.res, identity)
			}
		})
	}
}
