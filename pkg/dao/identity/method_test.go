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

	tests := []struct {
		inpIdent     *api.Identity
		resAlg       string
		resOTP       *oath.OTP
		resRetSecret bool
		err          error
	}{
		{
			&api.Identity{MethodOneof: &api.Identity_SoftwareHotpMethod{
				SoftwareHotpMethod: &api.SoftwareHOTPMethod{},
			}}, algHOTP, &oath.OTP{Hash: crypto.SHA512, Digits: defaultDigits},
			true, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_SoftwareTotpMethod{
				SoftwareTotpMethod: &api.SoftwareTOTPMethod{},
			}}, algTOTP, &oath.OTP{Hash: crypto.SHA512, Digits: defaultDigits},
			true, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_GoogleAuthHotpMethod{
				GoogleAuthHotpMethod: &api.GoogleAuthHOTPMethod{},
			}}, algHOTP, &oath.OTP{Hash: crypto.SHA512, Digits: defaultDigits},
			true, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_GoogleAuthTotpMethod{
				GoogleAuthTotpMethod: &api.GoogleAuthTOTPMethod{},
			}}, algTOTP, &oath.OTP{Hash: crypto.SHA512, Digits: defaultDigits},
			true, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_MicrosoftAuthTotpMethod{
				MicrosoftAuthTotpMethod: &api.MicrosoftAuthTOTPMethod{},
			}}, algTOTP, &oath.OTP{Hash: crypto.SHA1, Digits: 6}, true, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_HardwareHotpMethod{
				HardwareHotpMethod: &api.HardwareHOTPMethod{
					Digits: 8, Secret: key,
				},
			}}, algHOTP, &oath.OTP{Hash: crypto.SHA512, Digits: 8}, false, nil,
		},
		{
			&api.Identity{MethodOneof: &api.Identity_HardwareTotpMethod{
				HardwareTotpMethod: &api.HardwareTOTPMethod{
					Digits: 9, Secret: key,
				},
			}}, algTOTP, &oath.OTP{Hash: crypto.SHA512, Digits: 9}, false, nil,
		},
	}

	for _, test := range tests {
		lTest := test

		t.Run(fmt.Sprintf("Can convert %+v", lTest), func(t *testing.T) {
			t.Parallel()

			identity := random.Identity("dao-identity", uuid.NewString(),
				uuid.NewString())
			identity.MethodOneof = lTest.inpIdent.MethodOneof

			alg, otp, retSecret, err := methodToOTP(identity)
			t.Logf("alg, otp, retSecret, err: %v, %#v, %v, %v", alg, otp,
				retSecret, err)

			// Normalize secret.
			require.Len(t, otp.Key, 32)
			lTest.resOTP.Key = otp.Key

			require.Equal(t, lTest.resAlg, alg)
			require.Equal(t, lTest.resOTP, otp)
			require.Equal(t, lTest.resRetSecret, retSecret)
			require.Equal(t, lTest.err, err)
		})
	}
}

func TestOTPToMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		inpAlg    string
		inpHash   api.Hash
		inpDigits int32
		resIdent  *api.Identity
	}{
		{
			algHOTP, api.Hash_SHA512, defaultDigits, &api.Identity{
				MethodOneof: &api.Identity_GoogleAuthHotpMethod{
					GoogleAuthHotpMethod: &api.GoogleAuthHOTPMethod{},
				},
			},
		},
		{
			algTOTP, api.Hash_SHA512, defaultDigits, &api.Identity{
				MethodOneof: &api.Identity_GoogleAuthTotpMethod{
					GoogleAuthTotpMethod: &api.GoogleAuthTOTPMethod{},
				},
			},
		},
		{
			algTOTP, api.Hash_SHA1, 6, &api.Identity{
				MethodOneof: &api.Identity_MicrosoftAuthTotpMethod{
					MicrosoftAuthTotpMethod: &api.MicrosoftAuthTOTPMethod{},
				},
			},
		},
		{
			algHOTP, api.Hash_SHA512, 8, &api.Identity{
				MethodOneof: &api.Identity_SoftwareHotpMethod{
					SoftwareHotpMethod: &api.SoftwareHOTPMethod{
						Hash: api.Hash_SHA512, Digits: 8,
					},
				},
			},
		},
		{
			algTOTP, api.Hash_SHA256, 9, &api.Identity{
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
			otpToMethod(identity, lTest.inpAlg, lTest.inpHash, lTest.inpDigits)
			t.Logf("identity: %+v", identity)

			// Testify does not currently support protobuf equality:
			// https://github.com/stretchr/testify/issues/758
			if !proto.Equal(lTest.resIdent, identity) {
				t.Fatalf("\nExpect: %+v\nActual: %+v", lTest.resIdent, identity)
			}
		})
	}
}
