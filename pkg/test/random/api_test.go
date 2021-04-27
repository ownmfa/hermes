// +build !integration

package random

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestOrg(t *testing.T) {
	t.Parallel()

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can generate %v", lTest), func(t *testing.T) {
			t.Parallel()

			prefix := String(10)

			o1 := Org(prefix)
			o2 := Org(prefix)
			t.Logf("o1, o2: %+v, %+v", o1, o2)

			require.NotEqual(t, o1, o2)
			require.True(t, strings.HasPrefix(o1.Name, prefix))
			require.True(t, strings.HasPrefix(o2.Name, prefix))
			require.True(t, strings.HasPrefix(o1.DisplayName, prefix))
			require.True(t, strings.HasPrefix(o2.DisplayName, prefix))
			require.True(t, strings.HasPrefix(o1.Email, prefix))
			require.True(t, strings.HasPrefix(o2.Email, prefix))
		})
	}
}

func TestUser(t *testing.T) {
	t.Parallel()

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can generate %v", lTest), func(t *testing.T) {
			t.Parallel()

			prefix := String(10)
			orgID := uuid.NewString()

			u1 := User(prefix, orgID)
			u2 := User(prefix, orgID)
			t.Logf("u1, u2: %+v, %+v", u1, u2)

			require.NotEqual(t, u1, u2)
			require.True(t, strings.HasPrefix(u1.Name, prefix))
			require.True(t, strings.HasPrefix(u2.Name, prefix))
			require.True(t, strings.HasPrefix(u1.Email, prefix))
			require.True(t, strings.HasPrefix(u2.Email, prefix))
		})
	}
}

func TestKey(t *testing.T) {
	t.Parallel()

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can generate %v", lTest), func(t *testing.T) {
			t.Parallel()

			prefix := String(10)
			orgID := uuid.NewString()

			k1 := Key(prefix, orgID)
			k2 := Key(prefix, orgID)
			t.Logf("k1, k2: %+v, %+v", k1, k2)

			require.NotEqual(t, k1, k2)
			require.True(t, strings.HasPrefix(k1.Name, prefix))
			require.True(t, strings.HasPrefix(k2.Name, prefix))
		})
	}
}

func TestApp(t *testing.T) {
	t.Parallel()

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can generate %v", lTest), func(t *testing.T) {
			t.Parallel()

			prefix := String(10)
			orgID := uuid.NewString()

			a1 := App(prefix, orgID)
			a2 := App(prefix, orgID)
			t.Logf("a1, a2: %+v, %+v", a1, a2)

			require.NotEqual(t, a1, a2)
			require.True(t, strings.HasPrefix(a1.Name, prefix))
			require.True(t, strings.HasPrefix(a2.Name, prefix))
		})
	}
}

func TestIdentity(t *testing.T) {
	t.Parallel()

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can generate %v", lTest), func(t *testing.T) {
			t.Parallel()

			prefix := String(10)
			orgID := uuid.NewString()
			appID := uuid.NewString()

			a1 := Identity(prefix, orgID, appID)
			a2 := Identity(prefix, orgID, appID)
			t.Logf("a1, a2: %+v, %+v", a1, a2)

			require.NotEqual(t, a1, a2)
			require.True(t, strings.HasPrefix(a1.Comment, prefix))
			require.True(t, strings.HasPrefix(a2.Comment, prefix))
		})
	}
}
