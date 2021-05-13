// +build !integration

package key

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/stretchr/testify/require"
)

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

			require.Equal(t, fmt.Sprintf("api_notifier:hotpcounter:org:%s:app:"+
				"%s:identity:%s", orgID, appID, identityID), key)
			require.Equal(t, key, HOTPCounter(orgID, appID, identityID))
		})
	}
}

func TestExpire(t *testing.T) {
	t.Parallel()

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can key %v", lTest), func(t *testing.T) {
			t.Parallel()

			orgID := uuid.NewString()
			appID := uuid.NewString()
			identityID := uuid.NewString()
			passcode := random.String(10)

			key := Expire(orgID, appID, identityID, passcode)
			t.Logf("key: %v", key)

			require.Equal(t, fmt.Sprintf("api_notifier:expire:org:%s:app:%s:"+
				"identity:%s:passcode:%s", orgID, appID, identityID, passcode),
				key)
			require.Equal(t, key, Expire(orgID, appID, identityID, passcode))
		})
	}
}
