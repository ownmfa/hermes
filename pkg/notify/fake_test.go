//go:build !integration

package notify

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/stretchr/testify/require"
)

func TestNewFake(t *testing.T) {
	t.Parallel()

	notifier := NewFake()
	t.Logf("notifier: %#v", notifier)

	for i := range 5 {
		t.Run(fmt.Sprintf("Can notify %v", i), func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(t.Context(),
				2*time.Second)
			defer cancel()

			require.NoError(t, notifier.ValidateSMS(ctx, random.String(10)))
			require.NoError(t, notifier.SMS(ctx, random.String(10),
				random.String(10), random.String(10)))
			require.NoError(t, notifier.ValidatePushover(random.String(10)))
			require.NoError(t, notifier.Pushover(ctx, random.String(10),
				random.String(10), random.String(10)))
			require.NoError(t, notifier.PushoverByApp(ctx, random.String(10),
				random.String(10), random.String(10), random.String(10)))
			require.NoError(t, notifier.Email(ctx, random.String(10),
				random.String(10), random.String(10), random.String(10),
				random.String(10), random.String(10)))
		})
	}
}
