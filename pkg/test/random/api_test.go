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
			require.True(t, strings.HasPrefix(a1.DisplayName, prefix))
			require.True(t, strings.HasPrefix(a2.DisplayName, prefix))
			require.True(t, strings.HasPrefix(a1.Email, prefix))
			require.True(t, strings.HasPrefix(a2.Email, prefix))
		})
	}
}

func TestHOTPIdentity(t *testing.T) {
	t.Parallel()

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can generate %v", lTest), func(t *testing.T) {
			t.Parallel()

			prefix := String(10)
			orgID := uuid.NewString()
			appID := uuid.NewString()

			i1 := HOTPIdentity(prefix, orgID, appID)
			i2 := HOTPIdentity(prefix, orgID, appID)
			t.Logf("i1, i2: %+v, %+v", i1, i2)

			require.NotEqual(t, i1, i2)
			require.True(t, strings.HasPrefix(i1.Comment, prefix))
			require.True(t, strings.HasPrefix(i2.Comment, prefix))
		})
	}
}

func TestSMSIdentity(t *testing.T) {
	t.Parallel()

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can generate %v", lTest), func(t *testing.T) {
			t.Parallel()

			prefix := String(10)
			orgID := uuid.NewString()
			appID := uuid.NewString()

			i1 := SMSIdentity(prefix, orgID, appID)
			i2 := SMSIdentity(prefix, orgID, appID)
			t.Logf("i1, i2: %+v, %+v", i1, i2)

			require.NotEqual(t, i1, i2)
			require.True(t, strings.HasPrefix(i1.Comment, prefix))
			require.True(t, strings.HasPrefix(i2.Comment, prefix))
		})
	}
}

func TestPushoverIdentity(t *testing.T) {
	t.Parallel()

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can generate %v", lTest), func(t *testing.T) {
			t.Parallel()

			prefix := String(10)
			orgID := uuid.NewString()
			appID := uuid.NewString()

			i1 := PushoverIdentity(prefix, orgID, appID)
			i2 := PushoverIdentity(prefix, orgID, appID)
			t.Logf("i1, i2: %+v, %+v", i1, i2)

			require.NotEqual(t, i1, i2)
			require.True(t, strings.HasPrefix(i1.Comment, prefix))
			require.True(t, strings.HasPrefix(i2.Comment, prefix))
		})
	}
}

func TestEmailIdentity(t *testing.T) {
	t.Parallel()

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can generate %v", lTest), func(t *testing.T) {
			t.Parallel()

			prefix := String(10)
			orgID := uuid.NewString()
			appID := uuid.NewString()

			i1 := EmailIdentity(prefix, orgID, appID)
			i2 := EmailIdentity(prefix, orgID, appID)
			t.Logf("i1, i2: %+v, %+v", i1, i2)

			require.NotEqual(t, i1, i2)
			require.True(t, strings.HasPrefix(i1.Comment, prefix))
			require.True(t, strings.HasPrefix(i2.Comment, prefix))
		})
	}
}

func TestBackupCodesIdentity(t *testing.T) {
	t.Parallel()

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can generate %v", lTest), func(t *testing.T) {
			t.Parallel()

			prefix := String(10)
			orgID := uuid.NewString()
			appID := uuid.NewString()

			i1 := BackupCodesIdentity(prefix, orgID, appID)
			i2 := BackupCodesIdentity(prefix, orgID, appID)
			t.Logf("i1, i2: %+v, %+v", i1, i2)

			require.NotEqual(t, i1, i2)
			require.True(t, strings.HasPrefix(i1.Comment, prefix))
			require.True(t, strings.HasPrefix(i2.Comment, prefix))
		})
	}
}

func TestSecurityQuestionsIdentity(t *testing.T) {
	t.Parallel()

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can generate %v", lTest), func(t *testing.T) {
			t.Parallel()

			prefix := String(10)
			orgID := uuid.NewString()
			appID := uuid.NewString()

			i1 := SecurityQuestionsIdentity(prefix, orgID, appID)
			i2 := SecurityQuestionsIdentity(prefix, orgID, appID)
			t.Logf("i1, i2: %+v, %+v", i1, i2)

			require.NotEqual(t, i1, i2)
			require.True(t, strings.HasPrefix(i1.Comment, prefix))
			require.True(t, strings.HasPrefix(i2.Comment, prefix))
		})
	}
}

func TestEvent(t *testing.T) {
	t.Parallel()

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can generate %v", lTest), func(t *testing.T) {
			t.Parallel()

			prefix := String(10)
			orgID := uuid.NewString()

			e1 := Event(prefix, orgID)
			e2 := Event(prefix, orgID)
			t.Logf("e1, e2: %+v, %+v", e1, e2)

			require.NotEqual(t, e1, e2)
			if e1.Error != "" {
				require.True(t, strings.HasPrefix(e1.Error, prefix))
			}
			if e2.Error != "" {
				require.True(t, strings.HasPrefix(e2.Error, prefix))
			}
		})
	}
}
