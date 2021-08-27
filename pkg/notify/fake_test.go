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

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can notify %v", lTest), func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(),
				2*time.Second)
			defer cancel()

			require.NoError(t, notifier.VaildateSMS(ctx, random.String(10)))
			require.NoError(t, notifier.SMS(ctx, random.String(10),
				random.String(10), random.String(10)))
			require.NoError(t, notifier.VaildatePushover(ctx,
				random.String(10)))
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
