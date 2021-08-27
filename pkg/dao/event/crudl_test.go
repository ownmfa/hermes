//go:build !unit

package event

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/hermes/pkg/dao"
	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const testTimeout = 6 * time.Second

func TestCreate(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	createOrg, err := globalOrgDAO.Create(ctx, random.Org("dao-event"))
	t.Logf("createOrg, err: %+v, %v", createOrg, err)
	require.NoError(t, err)

	t.Run("Create valid events", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		err = globalEvDAO.Create(ctx, random.Event("dao-event", createOrg.Id))
		t.Logf("err: %v", err)
		require.NoError(t, err)
	})

	t.Run("Create invalid event", func(t *testing.T) {
		t.Parallel()

		event := random.Event("dao-event", createOrg.Id)
		event.Error = "dao-event-" + random.String(255)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		err := globalEvDAO.Create(ctx, event)
		t.Logf("err: %v", err)
		require.ErrorIs(t, err, dao.ErrInvalidFormat)
	})
}

func TestList(t *testing.T) {
	t.Parallel()

	t.Run("List events by valid org ID and identity ID", func(t *testing.T) {
		t.Parallel()

		identityID := uuid.NewString()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createOrg, err := globalOrgDAO.Create(ctx, random.Org("dao-event"))
		t.Logf("createOrg, err: %+v, %v", createOrg, err)
		require.NoError(t, err)

		events := []*api.Event{}

		for i := 0; i < 5; i++ {
			event := random.Event("dao-event", createOrg.Id)
			event.IdentityId = identityID
			events = append(events, event)

			ctx, cancel := context.WithTimeout(context.Background(),
				testTimeout)
			defer cancel()

			err := globalEvDAO.Create(ctx, event)
			t.Logf("err: %v", err)
			require.NoError(t, err)
		}

		sort.Slice(events, func(i, j int) bool {
			return events[i].CreatedAt.AsTime().After(
				events[j].CreatedAt.AsTime())
		})

		ctx, cancel = context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		// Verify results.
		listEvents, err := globalEvDAO.List(ctx, createOrg.Id, identityID,
			events[0].CreatedAt.AsTime(),
			events[len(events)-1].CreatedAt.AsTime().Add(-time.Millisecond))
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.NoError(t, err)
		require.Len(t, listEvents, len(events))

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		for i, event := range events {
			if !proto.Equal(event, listEvents[i]) {
				t.Fatalf("\nExpect: %+v\nActual: %+v", event, listEvents[i])
			}
		}
	})

	t.Run("Lists are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createOrg, err := globalOrgDAO.Create(ctx, random.Org("dao-event"))
		t.Logf("createOrg, err: %+v, %v", createOrg, err)
		require.NoError(t, err)

		event := random.Event("dao-event", createOrg.Id)

		err = globalEvDAO.Create(ctx, event)
		t.Logf("err: %#v", err)
		require.NoError(t, err)

		listEvents, err := globalEvDAO.List(ctx, uuid.NewString(),
			event.IdentityId, event.CreatedAt.AsTime(),
			event.CreatedAt.AsTime().Add(-time.Millisecond))
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.NoError(t, err)
		require.Len(t, listEvents, 0)
	})

	t.Run("List events by invalid org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		listEvents, err := globalEvDAO.List(ctx, random.String(10),
			uuid.NewString(), time.Now(), time.Now())
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.Nil(t, listEvents)
		require.ErrorIs(t, err, dao.ErrInvalidFormat)
	})
}

func TestLatest(t *testing.T) {
	t.Parallel()

	t.Run("Latest events", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createOrg, err := globalOrgDAO.Create(ctx, random.Org("dao-event"))
		t.Logf("createOrg, err: %+v, %v", createOrg, err)
		require.NoError(t, err)

		events := []*api.Event{}

		for i := 0; i < 5; i++ {
			event := random.Event("dao-event", createOrg.Id)
			events = append(events, event)

			ctx, cancel := context.WithTimeout(context.Background(),
				testTimeout)
			defer cancel()

			err := globalEvDAO.Create(ctx, event)
			t.Logf("err: %v", err)
			require.NoError(t, err)
		}

		sort.Slice(events, func(i, j int) bool {
			return events[i].CreatedAt.AsTime().After(
				events[j].CreatedAt.AsTime())
		})

		ctx, cancel = context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		// Verify results.
		latEvents, err := globalEvDAO.Latest(ctx, createOrg.Id, "", "")
		t.Logf("latEvents, err: %+v, %v", latEvents, err)
		require.NoError(t, err)
		require.Len(t, latEvents, len(events))

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		for i, event := range events {
			if !proto.Equal(event, latEvents[i]) {
				t.Fatalf("\nExpect: %+v\nActual: %+v", event, latEvents[i])
			}
		}

		// Verify results by app ID and identity ID.
		latEventsAppIDIdentityID, err := globalEvDAO.Latest(ctx, createOrg.Id,
			events[len(events)-1].AppId, events[len(events)-1].IdentityId)
		t.Logf("latEventsAppIDIdentityID, err: %+v, %v",
			latEventsAppIDIdentityID, err)
		require.NoError(t, err)
		require.Len(t, latEventsAppIDIdentityID, 1)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(events[len(events)-1], latEventsAppIDIdentityID[0]) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", events[len(events)-1],
				latEventsAppIDIdentityID[0])
		}

		// Verify results by app ID.
		latEventsAppID, err := globalEvDAO.Latest(ctx, createOrg.Id,
			events[0].AppId, "")
		t.Logf("latEventsAppID, err: %+v, %v", latEventsAppID, err)
		require.NoError(t, err)
		require.Len(t, latEventsAppID, 1)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(events[0], latEventsAppID[0]) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", events[0], latEventsAppID[0])
		}

		// Verify results by identity ID.
		latEventsIdentityID, err := globalEvDAO.Latest(ctx, createOrg.Id, "",
			events[1].IdentityId)
		t.Logf("latEventsIdentityID, err: %+v, %v", latEventsIdentityID, err)
		require.NoError(t, err)
		require.Len(t, latEventsIdentityID, 1)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(events[1], latEventsIdentityID[0]) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", events[1],
				latEventsIdentityID[0])
		}
	})

	t.Run("Latest events are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createOrg, err := globalOrgDAO.Create(ctx, random.Org("dao-event"))
		t.Logf("createOrg, err: %+v, %v", createOrg, err)
		require.NoError(t, err)

		event := random.Event("dao-event", createOrg.Id)

		err = globalEvDAO.Create(ctx, event)
		t.Logf("err: %#v", err)
		require.NoError(t, err)

		latEvents, err := globalEvDAO.Latest(ctx, uuid.NewString(), event.AppId,
			event.IdentityId)
		t.Logf("latEvents, err: %+v, %v", latEvents, err)
		require.NoError(t, err)
		require.Len(t, latEvents, 0)
	})

	t.Run("Latest events by invalid app ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		latEvents, err := globalEvDAO.Latest(ctx, uuid.NewString(),
			random.String(10), uuid.NewString())
		t.Logf("latEvents, err: %+v, %v", latEvents, err)
		require.Nil(t, latEvents)
		require.ErrorIs(t, err, dao.ErrInvalidFormat)
	})
}
