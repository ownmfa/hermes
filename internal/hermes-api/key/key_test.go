// +build !integration

package key

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
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
