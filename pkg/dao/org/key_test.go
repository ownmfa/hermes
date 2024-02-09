//go:build !integration

package org

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestOrgKey(t *testing.T) {
	t.Parallel()

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can key %v", lTest), func(t *testing.T) {
			t.Parallel()

			orgID := uuid.NewString()

			key := orgKey(orgID)
			t.Logf("key: %v", key)

			require.Equal(t, "dao:org:"+orgID, key)
			require.Equal(t, key, orgKey(orgID))
		})
	}
}
