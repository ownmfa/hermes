// +build !unit

package test

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestListEvents(t *testing.T) {
	t.Parallel()

	t.Run("List events by valid identity ID with ts", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		createApp, err := aiCli.CreateApp(ctx, &api.CreateAppRequest{
			App: random.App("api-event", uuid.NewString()),
		})
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.NoError(t, err)

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.HOTPIdentity("api-event", uuid.NewString(),
					createApp.Id),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		events := []*api.Event{}

		for i := 0; i < 5; i++ {
			event := random.Event("api-event", globalAdminOrgID)
			event.AppId = createApp.Id
			event.IdentityId = createIdentity.Identity.Id
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

		// Verify results by identity ID.
		evCli := api.NewEventServiceClient(globalAdminGRPCConn)
		listEvents, err := evCli.ListEvents(ctx, &api.ListEventsRequest{
			IdentityId: createIdentity.Identity.Id,
			EndTime:    events[0].CreatedAt,
			StartTime: timestamppb.New(events[len(events)-1].CreatedAt.
				AsTime().Add(-time.Microsecond)),
		})
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.NoError(t, err)
		require.Len(t, listEvents.Events, len(events))

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(&api.ListEventsResponse{Events: events}, listEvents) {
			t.Fatalf("\nExpect: %+v\nActual: %+v",
				&api.ListEventsResponse{Events: events}, listEvents)
		}

		// Verify results by identity ID without oldest event.
		listEventsTS, err := evCli.ListEvents(ctx, &api.ListEventsRequest{
			IdentityId: createIdentity.Identity.Id,
			StartTime:  events[len(events)-1].CreatedAt,
		})
		t.Logf("listEventsTS, err: %+v, %v", listEventsTS, err)
		require.NoError(t, err)
		require.Len(t, listEventsTS.Events, len(events)-1)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(&api.ListEventsResponse{Events: events[:len(events)-1]},
			listEventsTS) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", &api.ListEventsResponse{
				Events: events[:len(events)-1],
			}, listEventsTS)
		}
	})

	t.Run("List events are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createOrg, err := globalOrgDAO.Create(ctx, random.Org("api-event"))
		t.Logf("createOrg, err: %+v, %v", createOrg, err)
		require.NoError(t, err)

		event := random.Event("api-event", createOrg.Id)

		err = globalEvDAO.Create(ctx, event)
		t.Logf("err: %#v", err)
		require.NoError(t, err)

		evCli := api.NewEventServiceClient(globalAdminGRPCConn)
		listEvents, err := evCli.ListEvents(ctx, &api.ListEventsRequest{
			IdentityId: event.IdentityId,
		})
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.NoError(t, err)
		require.Len(t, listEvents.Events, 0)
	})

	t.Run("List events by invalid time range", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		evCli := api.NewEventServiceClient(globalAdminGRPCConn)
		listEvents, err := evCli.ListEvents(ctx, &api.ListEventsRequest{
			IdentityId: uuid.NewString(), EndTime: timestamppb.Now(),
			StartTime: timestamppb.New(time.Now().Add(-91 * 24 * time.Hour)),
		})
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.Nil(t, listEvents)
		require.EqualError(t, err, "rpc error: code = InvalidArgument desc = "+
			"maximum time range exceeded")
	})

	t.Run("List events by invalid identity ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		evCli := api.NewEventServiceClient(globalAdminGRPCConn)
		listEvents, err := evCli.ListEvents(ctx, &api.ListEventsRequest{
			IdentityId: random.String(10),
		})
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.Nil(t, listEvents)
		require.EqualError(t, err, "rpc error: code = InvalidArgument desc = "+
			"invalid ListEventsRequest.IdentityId: value must be a valid UUID "+
			"| caused by: invalid uuid format")
	})
}

func TestLatestEvents(t *testing.T) {
	t.Parallel()

	t.Run("Latest events", func(t *testing.T) {
		t.Parallel()

		events := []*api.Event{}

		for i := 0; i < 5; i++ {
			event := random.Event("api-event", globalAdminOrgID)
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

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		// Verify results.
		evCli := api.NewEventServiceClient(globalAdminGRPCConn)
		latEvents, err := evCli.LatestEvents(ctx, &api.LatestEventsRequest{})
		t.Logf("latEvents, err: %+v, %v", latEvents, err)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(latEvents.Events), 5)

		var found bool
		for _, event := range latEvents.Events {
			if event.AppId == events[len(events)-1].AppId &&
				event.IdentityId == events[len(events)-1].IdentityId {
				found = true
			}
		}
		require.True(t, found)

		// Verify results by app ID and identity ID.
		latEventsAppIDIdentityID, err := evCli.LatestEvents(ctx,
			&api.LatestEventsRequest{
				AppId:      events[len(events)-1].AppId,
				IdentityId: events[len(events)-1].IdentityId,
			})
		t.Logf("latEventsAppIDIdentityID, err: %+v, %v",
			latEventsAppIDIdentityID, err)
		require.NoError(t, err)
		require.Len(t, latEventsAppIDIdentityID.Events, 1)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(&api.LatestEventsResponse{
			Events: []*api.Event{events[len(events)-1]},
		}, latEventsAppIDIdentityID) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", &api.LatestEventsResponse{
				Events: []*api.Event{events[len(events)-1]},
			}, latEventsAppIDIdentityID)
		}

		// Verify results by app ID.
		latEventsAppID, err := evCli.LatestEvents(ctx,
			&api.LatestEventsRequest{AppId: events[0].AppId})
		t.Logf("latEventsAppID, err: %+v, %v", latEventsAppID, err)
		require.NoError(t, err)
		require.Len(t, latEventsAppID.Events, 1)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(&api.LatestEventsResponse{
			Events: []*api.Event{events[0]},
		}, latEventsAppID) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", &api.LatestEventsResponse{
				Events: []*api.Event{events[0]},
			}, latEventsAppID)
		}

		// Verify results by identity ID.
		latEventsIdentityID, err := evCli.LatestEvents(ctx,
			&api.LatestEventsRequest{IdentityId: events[1].IdentityId})
		t.Logf("latEventsIdentityID, err: %+v, %v", latEventsIdentityID, err)
		require.NoError(t, err)
		require.Len(t, latEventsIdentityID.Events, 1)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(&api.LatestEventsResponse{
			Events: []*api.Event{events[1]},
		}, latEventsIdentityID) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", &api.LatestEventsResponse{
				Events: []*api.Event{events[1]},
			}, latEventsIdentityID)
		}
	})

	t.Run("Latest events are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createOrg, err := globalOrgDAO.Create(ctx, random.Org("api-event"))
		t.Logf("createOrg, err: %+v, %v", createOrg, err)
		require.NoError(t, err)

		event := random.Event("api-event", createOrg.Id)

		err = globalEvDAO.Create(ctx, event)
		t.Logf("err: %#v", err)
		require.NoError(t, err)

		evCli := api.NewEventServiceClient(secondaryAdminGRPCConn)
		latEvents, err := evCli.LatestEvents(ctx, &api.LatestEventsRequest{})
		t.Logf("latEvents, err: %+v, %v", latEvents, err)
		require.NoError(t, err)
		require.Len(t, latEvents.Events, 0)
	})

	t.Run("Latest events by invalid identity ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		evCli := api.NewEventServiceClient(globalAdminGRPCConn)
		latEvents, err := evCli.LatestEvents(ctx, &api.LatestEventsRequest{
			IdentityId: random.String(10),
		})
		t.Logf("latEvents, err: %+v, %v", latEvents, err)
		require.Nil(t, latEvents)
		require.EqualError(t, err, "rpc error: code = InvalidArgument desc = "+
			"invalid LatestEventsRequest.IdentityId: value must be a valid "+
			"UUID | caused by: invalid uuid format")
	})
}