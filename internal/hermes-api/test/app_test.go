//go:build !unit

package test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/ownmfa/proto/go/api"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func TestCreateApp(t *testing.T) {
	t.Parallel()

	t.Run("Create valid app", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		createApp, err := aiCli.CreateApp(ctx,
			&api.CreateAppRequest{App: app})
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.NoError(t, err)
		require.NotEqual(t, app.GetId(), createApp.GetId())
		require.WithinDuration(t, time.Now(), createApp.GetCreatedAt().AsTime(),
			2*time.Second)
		require.WithinDuration(t, time.Now(), createApp.GetUpdatedAt().AsTime(),
			2*time.Second)
	})

	t.Run("Create valid app with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(secondaryViewerGRPCConn)
		createApp, err := aiCli.CreateApp(ctx, &api.CreateAppRequest{
			App: random.App("api-app", uuid.NewString()),
		})
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.Nil(t, createApp)
		require.EqualError(t, err, "rpc error: code = PermissionDenied desc = "+
			"permission denied, ADMIN role required")
	})

	t.Run("Create invalid app", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())
		app.Name = "api-app-" + random.String(40)

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		createApp, err := aiCli.CreateApp(ctx,
			&api.CreateAppRequest{App: app})
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.Nil(t, createApp)
		require.EqualError(t, err, "rpc error: code = InvalidArgument desc = "+
			"invalid CreateAppRequest.App: embedded message failed validation "+
			"| caused by: invalid App.Name: value length must be between 5 "+
			"and 40 runes, inclusive")
	})
}

func TestGetApp(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()

	aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
	createApp, err := aiCli.CreateApp(ctx, &api.CreateAppRequest{
		App: random.App("api-app", uuid.NewString()),
	})
	t.Logf("createApp, err: %+v, %v", createApp, err)
	require.NoError(t, err)

	t.Run("Get app by valid ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		getApp, err := aiCli.GetApp(ctx,
			&api.GetAppRequest{Id: createApp.GetId()})
		t.Logf("getApp, err: %+v, %v", getApp, err)
		require.NoError(t, err)
		require.EqualExportedValues(t, createApp, getApp)
	})

	t.Run("Get app by unknown ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		getApp, err := aiCli.GetApp(ctx,
			&api.GetAppRequest{Id: uuid.NewString()})
		t.Logf("getApp, err: %+v, %v", getApp, err)
		require.Nil(t, getApp)
		require.EqualError(t, err, "rpc error: code = NotFound desc = object "+
			"not found")
	})

	t.Run("Gets are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		secCli := api.NewAppIdentityServiceClient(secondaryAdminGRPCConn)
		getApp, err := secCli.GetApp(ctx,
			&api.GetAppRequest{Id: createApp.GetId()})
		t.Logf("getApp, err: %+v, %v", getApp, err)
		require.Nil(t, getApp)
		require.EqualError(t, err, "rpc error: code = NotFound desc = object "+
			"not found")
	})
}

func TestUpdateApp(t *testing.T) {
	t.Parallel()

	t.Run("Update app by valid app", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		createApp, err := aiCli.CreateApp(ctx,
			&api.CreateAppRequest{App: app})
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.NoError(t, err)

		// Update app fields.
		createApp.Name = "api-app-" + random.String(10)
		createApp.DisplayName = "api-app-" + random.String(10)
		createApp.Email = "api-app-" + random.Email()
		createApp.PushoverKey = "api-app-" + random.String(30)

		updateApp, err := aiCli.UpdateApp(ctx,
			&api.UpdateAppRequest{App: createApp})
		t.Logf("updateApp, err: %+v, %v", updateApp, err)
		require.NoError(t, err)
		require.Equal(t, createApp.GetName(), updateApp.GetName())
		require.Equal(t, createApp.GetDisplayName(), updateApp.GetDisplayName())
		require.Equal(t, createApp.GetEmail(), updateApp.GetEmail())
		require.Equal(t, createApp.GetPushoverKey(), updateApp.GetPushoverKey())
		require.True(t, updateApp.GetUpdatedAt().AsTime().After(
			updateApp.GetCreatedAt().AsTime()))
		require.WithinDuration(t, createApp.GetCreatedAt().AsTime(),
			updateApp.GetUpdatedAt().AsTime(), 2*time.Second)

		getApp, err := aiCli.GetApp(ctx,
			&api.GetAppRequest{Id: createApp.GetId()})
		t.Logf("getApp, err: %+v, %v", getApp, err)
		require.NoError(t, err)
		require.EqualExportedValues(t, updateApp, getApp)
	})

	t.Run("Partial update app by valid app", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminKeyGRPCConn)
		createApp, err := aiCli.CreateApp(ctx,
			&api.CreateAppRequest{App: app})
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.NoError(t, err)

		// Update app fields.
		part := &api.App{
			Id: createApp.GetId(), Name: "api-app-" + random.String(10),
			DisplayName: "api-app-" + random.String(10), Email: "api-app-" +
				random.Email(), PushoverKey: "api-app-" + random.String(30),
		}

		updateApp, err := aiCli.UpdateApp(ctx, &api.UpdateAppRequest{
			App: part, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{
				"name", "display_name", "email", "pushover_key",
			}},
		})
		t.Logf("updateApp, err: %+v, %v", updateApp, err)
		require.NoError(t, err)
		require.Equal(t, part.GetName(), updateApp.GetName())
		require.Equal(t, part.GetDisplayName(), updateApp.GetDisplayName())
		require.Equal(t, part.GetEmail(), updateApp.GetEmail())
		require.Equal(t, part.GetPushoverKey(), updateApp.GetPushoverKey())
		require.True(t, updateApp.GetUpdatedAt().AsTime().After(
			updateApp.GetCreatedAt().AsTime()))
		require.WithinDuration(t, createApp.GetCreatedAt().AsTime(),
			updateApp.GetUpdatedAt().AsTime(), 2*time.Second)

		getApp, err := aiCli.GetApp(ctx,
			&api.GetAppRequest{Id: createApp.GetId()})
		t.Logf("getApp, err: %+v, %v", getApp, err)
		require.NoError(t, err)
		require.EqualExportedValues(t, updateApp, getApp)
	})

	t.Run("Update nil app", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		updateApp, err := aiCli.UpdateApp(ctx,
			&api.UpdateAppRequest{App: nil})
		t.Logf("updateApp, err: %+v, %v", updateApp, err)
		require.Nil(t, updateApp)
		require.EqualError(t, err, "rpc error: code = InvalidArgument desc = "+
			"invalid UpdateAppRequest.App: value is required")
	})

	t.Run("Update app with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(secondaryViewerGRPCConn)
		updateApp, err := aiCli.UpdateApp(ctx, &api.UpdateAppRequest{
			App: random.App("api-app", uuid.NewString()),
		})
		t.Logf("updateApp, err: %+v, %v", updateApp, err)
		require.Nil(t, updateApp)
		require.EqualError(t, err, "rpc error: code = PermissionDenied desc = "+
			"permission denied, ADMIN role required")
	})

	t.Run("Update app with insufficient key role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(secondaryViewerKeyGRPCConn)
		updateApp, err := aiCli.UpdateApp(ctx, &api.UpdateAppRequest{
			App: random.App("api-app", uuid.NewString()),
		})
		t.Logf("updateApp, err: %+v, %v", updateApp, err)
		require.Nil(t, updateApp)
		require.EqualError(t, err, "rpc error: code = PermissionDenied desc = "+
			"permission denied, ADMIN role required")
	})

	t.Run("Partial update invalid field mask", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		updateApp, err := aiCli.UpdateApp(ctx, &api.UpdateAppRequest{
			App: app, UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"aaa"},
			},
		})
		t.Logf("updateApp, err: %+v, %v", updateApp, err)
		require.Nil(t, updateApp)
		require.EqualError(t, err, "rpc error: code = InvalidArgument desc = "+
			"invalid field mask")
	})

	t.Run("Partial update app by unknown app", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		updateApp, err := aiCli.UpdateApp(ctx, &api.UpdateAppRequest{
			App: app, UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"name"},
			},
		})
		t.Logf("updateApp, err: %+v, %v", updateApp, err)
		require.Nil(t, updateApp)
		require.EqualError(t, err, "rpc error: code = NotFound desc = object "+
			"not found")
	})

	t.Run("Update app by unknown app", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		updateApp, err := aiCli.UpdateApp(ctx,
			&api.UpdateAppRequest{App: app})
		t.Logf("updateApp, err: %+v, %v", updateApp, err)
		require.Nil(t, updateApp)
		require.EqualError(t, err, "rpc error: code = NotFound desc = object "+
			"not found")
	})

	t.Run("Updates are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		createApp, err := aiCli.CreateApp(ctx,
			&api.CreateAppRequest{App: app})
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.NoError(t, err)

		// Update app fields.
		createApp.OrgId = uuid.NewString()
		createApp.Name = "api-app-" + random.String(10)

		secCli := api.NewAppIdentityServiceClient(secondaryAdminGRPCConn)
		updateApp, err := secCli.UpdateApp(ctx,
			&api.UpdateAppRequest{App: createApp})
		t.Logf("updateApp, err: %+v, %v", updateApp, err)
		require.Nil(t, updateApp)
		require.EqualError(t, err, "rpc error: code = NotFound desc = object "+
			"not found")
	})

	t.Run("Update app validation failure", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		createApp, err := aiCli.CreateApp(ctx,
			&api.CreateAppRequest{App: app})
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.NoError(t, err)

		// Update app fields.
		createApp.Name = "api-app-" + random.String(40)

		updateApp, err := aiCli.UpdateApp(ctx,
			&api.UpdateAppRequest{App: createApp})
		t.Logf("updateApp, err: %+v, %v", updateApp, err)
		require.Nil(t, updateApp)
		require.EqualError(t, err, "rpc error: code = InvalidArgument desc = "+
			"invalid UpdateAppRequest.App: embedded message failed validation "+
			"| caused by: invalid App.Name: value length must be between 5 "+
			"and 40 runes, inclusive")
	})
}

func TestDeleteApp(t *testing.T) {
	t.Parallel()

	t.Run("Delete app by valid ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		createApp, err := aiCli.CreateApp(ctx, &api.CreateAppRequest{
			App: random.App("api-app", uuid.NewString()),
		})
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.NoError(t, err)

		_, err = aiCli.DeleteApp(ctx,
			&api.DeleteAppRequest{Id: createApp.GetId()})
		t.Logf("err: %v", err)
		require.NoError(t, err)

		t.Run("Read app by deleted ID", func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(t.Context(),
				testTimeout)
			defer cancel()

			aiCli := api.NewAppIdentityServiceClient(globalAdminKeyGRPCConn)
			getApp, err := aiCli.GetApp(ctx,
				&api.GetAppRequest{Id: createApp.GetId()})
			t.Logf("getApp, err: %+v, %v", getApp, err)
			require.Nil(t, getApp)
			require.EqualError(t, err, "rpc error: code = NotFound desc = "+
				"object not found")
		})
	})

	t.Run("Delete app with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(secondaryViewerGRPCConn)
		_, err := aiCli.DeleteApp(ctx,
			&api.DeleteAppRequest{Id: uuid.NewString()})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = PermissionDenied "+
			"desc = permission denied, ADMIN role required")
	})

	t.Run("Delete app by unknown ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		_, err := aiCli.DeleteApp(ctx,
			&api.DeleteAppRequest{Id: uuid.NewString()})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = NotFound desc = object "+
			"not found")
	})

	t.Run("Deletes are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		createApp, err := aiCli.CreateApp(ctx, &api.CreateAppRequest{
			App: random.App("api-app", uuid.NewString()),
		})
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.NoError(t, err)

		secCli := api.NewAppIdentityServiceClient(secondaryAdminGRPCConn)
		_, err = secCli.DeleteApp(ctx,
			&api.DeleteAppRequest{Id: createApp.GetId()})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = NotFound desc = object "+
			"not found")
	})
}

func TestListApps(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()

	appIDs := []string{}
	appNames := []string{}
	for range 3 {
		app := random.App("api-app", uuid.NewString())

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		createApp, err := aiCli.CreateApp(ctx,
			&api.CreateAppRequest{App: app})
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.NoError(t, err)

		appIDs = append(appIDs, createApp.GetId())
		appNames = append(appNames, createApp.GetName())
	}

	t.Run("List apps by valid org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		listApps, err := aiCli.ListApps(ctx, &api.ListAppsRequest{})
		t.Logf("listApps, err: %+v, %v", listApps, err)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(listApps.GetApps()), 3)
		require.GreaterOrEqual(t, listApps.GetTotalSize(), int32(3))

		var found bool
		for _, app := range listApps.GetApps() {
			if app.GetId() == appIDs[len(appIDs)-1] &&
				app.GetName() == appNames[len(appNames)-1] {
				found = true
			}
		}
		require.True(t, found)
	})

	t.Run("List apps by valid org ID with next page", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminKeyGRPCConn)
		listApps, err := aiCli.ListApps(ctx,
			&api.ListAppsRequest{PageSize: 2})
		t.Logf("listApps, err: %+v, %v", listApps, err)
		require.NoError(t, err)
		require.Len(t, listApps.GetApps(), 2)
		require.NotEmpty(t, listApps.GetNextPageToken())
		require.GreaterOrEqual(t, listApps.GetTotalSize(), int32(3))

		nextApps, err := aiCli.ListApps(ctx, &api.ListAppsRequest{
			PageSize: 2, PageToken: listApps.GetNextPageToken(),
		})
		t.Logf("nextApps, err: %+v, %v", nextApps, err)
		require.NoError(t, err)
		require.NotEmpty(t, nextApps.GetApps())
		require.GreaterOrEqual(t, nextApps.GetTotalSize(), int32(3))
	})

	t.Run("Lists are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		secCli := api.NewAppIdentityServiceClient(secondaryAdminGRPCConn)
		listApps, err := secCli.ListApps(ctx, &api.ListAppsRequest{})
		t.Logf("listApps, err: %+v, %v", listApps, err)
		require.NoError(t, err)
		require.Empty(t, listApps.GetApps())
		require.Equal(t, int32(0), listApps.GetTotalSize())
	})

	t.Run("List apps by invalid page token", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		listApps, err := aiCli.ListApps(ctx,
			&api.ListAppsRequest{PageToken: badUUID})
		t.Logf("listApps, err: %+v, %v", listApps, err)
		require.Nil(t, listApps)
		require.EqualError(t, err, "rpc error: code = InvalidArgument desc = "+
			"invalid page token")
	})
}
