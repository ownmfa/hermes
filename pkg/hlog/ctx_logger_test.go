//go:build !integration

package hlog

import (
	"context"
	"testing"
	"time"

	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/stretchr/testify/require"
)

const testTimeout = 2 * time.Second

func TestNewFromContext(t *testing.T) {
	t.Parallel()

	logger := &CtxLogger{Logger: WithField(random.String(10), random.String(10))}
	t.Logf("logger: %+v", logger)

	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()

	ctx = NewContext(ctx, logger)
	ctxLogger := FromContext(ctx)
	t.Logf("ctxLogger: %+v", ctxLogger)
	require.Equal(t, logger, ctxLogger)
}

func TestFromContextDefault(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()

	ctxLogger := FromContext(ctx)
	t.Logf("ctxLogger: %+v", ctxLogger)
	require.Equal(t, &CtxLogger{Logger: Default()}, ctxLogger)
}
