//go:build !unit

package test

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/ownmfa/proto/go/api"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestListEvents(t *testing.T) {
	t.Parallel()

	t.Run("List events by valid identity ID with ts", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
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
					createApp.GetId()),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		events := []*api.Event{}

		for range 5 {
			event := random.Event("api-event", globalAdminOrgID)
			event.AppId = createApp.GetId()
			event.IdentityId = createIdentity.GetIdentity().GetId()
			events = append(events, event)

			ctx, cancel := context.WithTimeout(t.Context(),
				testTimeout)
			defer cancel()

			err := globalEvDAO.Create(ctx, event)
			t.Logf("err: %v", err)
			require.NoError(t, err)
		}

		sort.Slice(events, func(i, j int) bool {
			return events[i].GetCreatedAt().AsTime().After(
				events[j].GetCreatedAt().AsTime())
		})

		ctx, cancel = context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		// Verify results by identity ID.
		evCli := api.NewEventServiceClient(globalAdminGRPCConn)
		listEvents, err := evCli.ListEvents(ctx, &api.ListEventsRequest{
			IdentityId: createIdentity.GetIdentity().GetId(),
			EndTime:    events[0].GetCreatedAt(),
			StartTime: timestamppb.New(events[len(events)-1].GetCreatedAt().
				AsTime().Add(-time.Microsecond)),
		})
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.NoError(t, err)
		require.Len(t, listEvents.GetEvents(), len(events))
		require.EqualExportedValues(t, &api.ListEventsResponse{Events: events},
			listEvents)

		// Verify results by identity ID without oldest event.
		listEventsTS, err := evCli.ListEvents(ctx, &api.ListEventsRequest{
			IdentityId: createIdentity.GetIdentity().GetId(),
			StartTime:  events[len(events)-1].GetCreatedAt(),
		})
		t.Logf("listEventsTS, err: %+v, %v", listEventsTS, err)
		require.NoError(t, err)
		require.Len(t, listEventsTS.GetEvents(), len(events)-1)
		require.EqualExportedValues(t, &api.ListEventsResponse{
			Events: events[:len(events)-1],
		}, listEventsTS)
	})

	t.Run("List events are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		createOrg, err := globalOrgDAO.Create(ctx, random.Org("api-event"))
		t.Logf("createOrg, err: %+v, %v", createOrg, err)
		require.NoError(t, err)

		event := random.Event("api-event", createOrg.GetId())

		err = globalEvDAO.Create(ctx, event)
		t.Logf("err: %#v", err)
		require.NoError(t, err)

		evCli := api.NewEventServiceClient(globalAdminGRPCConn)
		listEvents, err := evCli.ListEvents(ctx, &api.ListEventsRequest{
			IdentityId: event.GetIdentityId(),
		})
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.NoError(t, err)
		require.Empty(t, listEvents.GetEvents())
	})

	t.Run("List events by invalid time range", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
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

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
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

		for range 5 {
			event := random.Event("api-event", globalAdminOrgID)
			events = append(events, event)

			ctx, cancel := context.WithTimeout(t.Context(),
				testTimeout)
			defer cancel()

			err := globalEvDAO.Create(ctx, event)
			t.Logf("err: %v", err)
			require.NoError(t, err)
		}

		sort.Slice(events, func(i, j int) bool {
			return events[i].GetCreatedAt().AsTime().After(
				events[j].GetCreatedAt().AsTime())
		})

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		// Verify results.
		evCli := api.NewEventServiceClient(globalAdminGRPCConn)
		latEvents, err := evCli.LatestEvents(ctx, &api.LatestEventsRequest{})
		t.Logf("latEvents, err: %+v, %v", latEvents, err)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(latEvents.GetEvents()), 5)

		var found bool
		for _, event := range latEvents.GetEvents() {
			if event.GetAppId() == events[len(events)-1].GetAppId() &&
				event.GetIdentityId() == events[len(events)-1].GetIdentityId() {
				found = true
			}
		}
		require.True(t, found)

		// Verify results by app ID and identity ID.
		latEventsAppIDIdentityID, err := evCli.LatestEvents(ctx,
			&api.LatestEventsRequest{
				AppId:      events[len(events)-1].GetAppId(),
				IdentityId: events[len(events)-1].GetIdentityId(),
			})
		t.Logf("latEventsAppIDIdentityID, err: %+v, %v",
			latEventsAppIDIdentityID, err)
		require.NoError(t, err)
		require.Len(t, latEventsAppIDIdentityID.GetEvents(), 1)
		require.EqualExportedValues(t, &api.LatestEventsResponse{
			Events: []*api.Event{events[len(events)-1]},
		}, latEventsAppIDIdentityID)

		// Verify results by app ID.
		latEventsAppID, err := evCli.LatestEvents(ctx,
			&api.LatestEventsRequest{AppId: events[0].GetAppId()})
		t.Logf("latEventsAppID, err: %+v, %v", latEventsAppID, err)
		require.NoError(t, err)
		require.Len(t, latEventsAppID.GetEvents(), 1)
		require.EqualExportedValues(t, &api.LatestEventsResponse{
			Events: []*api.Event{events[0]},
		}, latEventsAppID)

		// Verify results by identity ID.
		latEventsIdentityID, err := evCli.LatestEvents(ctx,
			&api.LatestEventsRequest{IdentityId: events[1].GetIdentityId()})
		t.Logf("latEventsIdentityID, err: %+v, %v", latEventsIdentityID, err)
		require.NoError(t, err)
		require.Len(t, latEventsIdentityID.GetEvents(), 1)
		require.EqualExportedValues(t, &api.LatestEventsResponse{
			Events: []*api.Event{events[1]},
		}, latEventsIdentityID)
	})

	t.Run("Latest events are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		createOrg, err := globalOrgDAO.Create(ctx, random.Org("api-event"))
		t.Logf("createOrg, err: %+v, %v", createOrg, err)
		require.NoError(t, err)

		event := random.Event("api-event", createOrg.GetId())

		err = globalEvDAO.Create(ctx, event)
		t.Logf("err: %#v", err)
		require.NoError(t, err)

		evCli := api.NewEventServiceClient(secondaryAdminGRPCConn)
		latEvents, err := evCli.LatestEvents(ctx, &api.LatestEventsRequest{})
		t.Logf("latEvents, err: %+v, %v", latEvents, err)
		require.NoError(t, err)
		require.Empty(t, latEvents.GetEvents())
	})

	t.Run("Latest events by invalid identity ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
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
