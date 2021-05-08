// +build !integration

package key

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/stretchr/testify/require"
)

func TestDisabled(t *testing.T) {
	t.Parallel()

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can key %v", lTest), func(t *testing.T) {
			t.Parallel()

			orgID := uuid.NewString()
			keyID := uuid.NewString()

			key := Disabled(orgID, keyID)
			t.Logf("key: %v", key)

			require.Equal(t, fmt.Sprintf("api:disabled:org:%s:key:%s", orgID,
				keyID), key)
			require.Equal(t, key, Disabled(orgID, keyID))
		})
	}
}

func TestHOTPCounter(t *testing.T) {
	t.Parallel()

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can key %v", lTest), func(t *testing.T) {
			t.Parallel()

			orgID := uuid.NewString()
			appID := uuid.NewString()
			identityID := uuid.NewString()

			key := HOTPCounter(orgID, appID, identityID)
			t.Logf("key: %v", key)

			require.Equal(t, fmt.Sprintf("api:hotpcounter:org:%s:app:%s:"+
				"identity:%s", orgID, appID, identityID), key)
			require.Equal(t, key, HOTPCounter(orgID, appID, identityID))
		})
	}
}

func TestTOTPOffset(t *testing.T) {
	t.Parallel()

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can key %v", lTest), func(t *testing.T) {
			t.Parallel()

			orgID := uuid.NewString()
			appID := uuid.NewString()
			identityID := uuid.NewString()

			key := TOTPOffset(orgID, appID, identityID)
			t.Logf("key: %v", key)

			require.Equal(t, fmt.Sprintf("api:totpoffset:org:%s:app:%s:"+
				"identity:%s", orgID, appID, identityID), key)
			require.Equal(t, key, TOTPOffset(orgID, appID, identityID))
		})
	}
}

func TestReuse(t *testing.T) {
	t.Parallel()

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can key %v", lTest), func(t *testing.T) {
			t.Parallel()

			orgID := uuid.NewString()
			appID := uuid.NewString()
			identityID := uuid.NewString()
			passcode := random.String(10)

			key := Reuse(orgID, appID, identityID, passcode)
			t.Logf("key: %v", key)

			require.Equal(t, fmt.Sprintf("api:reuse:org:%s:app:%s:identity:%s:"+
				"passcode:%s", orgID, appID, identityID, passcode), key)
			require.Equal(t, key, Reuse(orgID, appID, identityID, passcode))
		})
	}
}

func TestChallenge(t *testing.T) {
	t.Parallel()

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can key %v", lTest), func(t *testing.T) {
			t.Parallel()

			orgID := uuid.NewString()
			appID := uuid.NewString()
			identityID := uuid.NewString()

			key := Challenge(orgID, appID, identityID)
			t.Logf("key: %v", key)

			require.Equal(t, fmt.Sprintf("api:challenge:org:%s:app:%s:"+
				"identity:%s", orgID, appID, identityID), key)
			require.Equal(t, key, Challenge(orgID, appID, identityID))
		})
	}
}
