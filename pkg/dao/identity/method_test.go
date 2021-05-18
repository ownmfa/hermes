// +build !integration

package identity

import (
	"crypto"
	"crypto/rand"
	"fmt"
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
	inpPhone := random.String(10)
	inpPushoverKey := random.String(10)

	tests := []struct {
		inpIdentity    *api.Identity
		resOTP         *oath.OTP
		resPhone       string
		resPushoverKey string
		resRetSecret   bool
		err            error
	}{
		{
			&api.Identity{MethodOneof: &api.Identity_SoftwareHotpMethod{
				SoftwareHotpMethod: &api.SoftwareHOTPMethod{AccountName: email},
			}}, &oath.OTP{
				Algorithm: oath.HOTP, Hash: crypto.SHA512,
				Digits: defaultDigits, AccountName: email,
			}, "", "", true, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_SoftwareTotpMethod{
				SoftwareTotpMethod: &api.SoftwareTOTPMethod{},
			}}, &oath.OTP{
				Algorithm: oath.TOTP, Hash: crypto.SHA512,
				Digits: defaultDigits,
			}, "", "", true, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_GoogleAuthHotpMethod{
				GoogleAuthHotpMethod: &api.GoogleAuthHOTPMethod{},
			}}, &oath.OTP{
				Algorithm: oath.HOTP, Hash: crypto.SHA1, Digits: 6,
			}, "", "", true, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_GoogleAuthTotpMethod{
				GoogleAuthTotpMethod: &api.GoogleAuthTOTPMethod{
					AccountName: email,
				},
			}}, &oath.OTP{
				Algorithm: oath.TOTP, Hash: crypto.SHA1, Digits: 6,
				AccountName: email,
			}, "", "", true, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_HardwareHotpMethod{
				HardwareHotpMethod: &api.HardwareHOTPMethod{
					Digits: 8, Secret: key,
				},
			}}, &oath.OTP{
				Algorithm: oath.HOTP, Hash: crypto.SHA512, Digits: 8,
			}, "", "", false, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_HardwareTotpMethod{
				HardwareTotpMethod: &api.HardwareTOTPMethod{
					Digits: 9, Secret: key,
				},
			}}, &oath.OTP{
				Algorithm: oath.TOTP, Hash: crypto.SHA512, Digits: 9,
			}, "", "", false, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_SmsMethod{
				SmsMethod: &api.SMSMethod{Phone: inpPhone},
			}}, &oath.OTP{
				Algorithm: oath.HOTP, Hash: crypto.SHA512,
				Digits: defaultDigits,
			}, inpPhone, "", false, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_PushoverMethod{
				PushoverMethod: &api.PushoverMethod{
					PushoverKey: inpPushoverKey,
				},
			}}, &oath.OTP{
				Algorithm: oath.HOTP, Hash: crypto.SHA512,
				Digits: defaultDigits,
			}, "", inpPushoverKey, false, nil,
		},
		{
			&api.Identity{MethodOneof: nil}, nil, "", "", false,
			errUnknownMethodOneof,
		},
	}

	for _, test := range tests {
		lTest := test

		t.Run(fmt.Sprintf("Can convert %+v", lTest), func(t *testing.T) {
			t.Parallel()

			identity := random.HOTPIdentity("dao-identity", uuid.NewString(),
				uuid.NewString())
			identity.MethodOneof = lTest.inpIdentity.MethodOneof

			otp, phone, pushoverKey, retSecret, err := methodToOTP(identity)
			t.Logf("otp, phone, pushoverKey, retSecret, err: %#v, %v, %v, %v, "+
				"%v", otp, phone, pushoverKey, retSecret, err)

			// Normalize secret.
			if lTest.resOTP != nil {
				require.Len(t, otp.Key, 32)
				lTest.resOTP.Key = otp.Key
			}

			require.Equal(t, lTest.resOTP, otp)
			require.Equal(t, lTest.resPhone, phone)
			require.Equal(t, lTest.resPushoverKey, pushoverKey)
			require.Equal(t, lTest.resRetSecret, retSecret)
			require.Equal(t, lTest.err, err)
		})
	}
}

func TestOTPToMethod(t *testing.T) {
	t.Parallel()

	phone := random.String(10)
	pushoverKey := random.String(30)

	tests := []struct {
		inpPhone       string
		inpPushoverKey string
		inpAlg         string
		inpHash        api.Hash
		inpDigits      int32
		resIdentity    *api.Identity
	}{
		{
			"", pushoverKey, oath.HOTP, api.Hash_SHA512, defaultDigits,
			&api.Identity{MethodOneof: &api.Identity_PushoverMethod{
				PushoverMethod: &api.PushoverMethod{PushoverKey: pushoverKey},
			}},
		},
		{
			phone, "", oath.HOTP, api.Hash_SHA512, defaultDigits, &api.Identity{
				MethodOneof: &api.Identity_SmsMethod{
					SmsMethod: &api.SMSMethod{Phone: phone},
				},
			},
		},
		{
			"", "", oath.HOTP, api.Hash_SHA1, 6, &api.Identity{
				MethodOneof: &api.Identity_GoogleAuthHotpMethod{
					GoogleAuthHotpMethod: &api.GoogleAuthHOTPMethod{},
				},
			},
		},
		{
			"", "", oath.TOTP, api.Hash_SHA1, 6, &api.Identity{
				MethodOneof: &api.Identity_GoogleAuthTotpMethod{
					GoogleAuthTotpMethod: &api.GoogleAuthTOTPMethod{},
				},
			},
		},
		{
			"", "", oath.HOTP, api.Hash_SHA512, 8, &api.Identity{
				MethodOneof: &api.Identity_SoftwareHotpMethod{
					SoftwareHotpMethod: &api.SoftwareHOTPMethod{
						Hash: api.Hash_SHA512, Digits: 8,
					},
				},
			},
		},
		{
			"", "", oath.TOTP, api.Hash_SHA256, 9, &api.Identity{
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
			otpToMethod(identity, lTest.inpPhone, lTest.inpPushoverKey, lTest.inpAlg, lTest.inpHash,
				lTest.inpDigits)
			t.Logf("identity: %+v", identity)

			// Testify does not currently support protobuf equality:
			// https://github.com/stretchr/testify/issues/758
			if !proto.Equal(lTest.resIdentity, identity) {
				t.Fatalf("\nExpect: %+v\nActual: %+v", lTest.resIdentity,
					identity)
			}
		})
	}
}
