//go:build !unit

package app

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ownmfa/hermes/pkg/dao"
	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/ownmfa/proto/go/api"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const testTimeout = 8 * time.Second

func TestCreate(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()

	createOrg, err := globalOrgDAO.Create(ctx, random.Org("dao-app"))
	t.Logf("createOrg, err: %+v, %v", createOrg, err)
	require.NoError(t, err)

	t.Run("Create valid app", func(t *testing.T) {
		t.Parallel()

		app := random.App("dao-app", createOrg.GetId())
		createApp, _ := proto.Clone(app).(*api.App)

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		createApp, err := globalAppDAO.Create(ctx, createApp)
		t.Logf("app, createApp, err: %+v, %+v, %v", app, createApp, err)
		require.NoError(t, err)
		require.NotEqual(t, app.GetId(), createApp.GetId())
		require.WithinDuration(t, time.Now(), createApp.GetCreatedAt().AsTime(),
			2*time.Second)
		require.WithinDuration(t, time.Now(), createApp.GetUpdatedAt().AsTime(),
			2*time.Second)
	})

	t.Run("Create invalid app", func(t *testing.T) {
		t.Parallel()

		app := random.App("dao-app", createOrg.GetId())
		app.Name = "dao-app-" + random.String(40)

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		createApp, err := globalAppDAO.Create(ctx, app)
		t.Logf("app, createApp, err: %+v, %+v, %v", app, createApp, err)
		require.Nil(t, createApp)
		require.ErrorIs(t, err, dao.ErrInvalidFormat)
	})
}

func TestRead(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()

	createOrg, err := globalOrgDAO.Create(ctx, random.Org("dao-app"))
	t.Logf("createOrg, err: %+v, %v", createOrg, err)
	require.NoError(t, err)

	createApp, err := globalAppDAO.Create(ctx, random.App("dao-app",
		createOrg.GetId()))
	t.Logf("createApp, err: %+v, %v", createApp, err)
	require.NoError(t, err)

	t.Run("Read app by valid ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		readApp, err := globalAppDAO.Read(ctx, createApp.GetId(), createApp.GetOrgId())
		t.Logf("readApp, err: %+v, %v", readApp, err)
		require.NoError(t, err)
		require.Equal(t, createApp, readApp)
	})

	t.Run("Read app by unknown ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		readApp, err := globalAppDAO.Read(ctx, uuid.NewString(),
			uuid.NewString())
		t.Logf("readApp, err: %+v, %v", readApp, err)
		require.Nil(t, readApp)
		require.Equal(t, dao.ErrNotFound, err)
	})

	t.Run("Reads are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		readApp, err := globalAppDAO.Read(ctx, createApp.GetId(),
			uuid.NewString())
		t.Logf("readApp, err: %+v, %v", readApp, err)
		require.Nil(t, readApp)
		require.Equal(t, dao.ErrNotFound, err)
	})

	t.Run("Read app by invalid ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		readApp, err := globalAppDAO.Read(ctx, random.String(10),
			createApp.GetOrgId())
		t.Logf("readApp, err: %+v, %v", readApp, err)
		require.Nil(t, readApp)
		require.ErrorIs(t, err, dao.ErrInvalidFormat)
	})
}

func TestUpdate(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()

	createOrg, err := globalOrgDAO.Create(ctx, random.Org("dao-app"))
	t.Logf("createOrg, err: %+v, %v", createOrg, err)
	require.NoError(t, err)

	t.Run("Update app by valid app", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		createApp, err := globalAppDAO.Create(ctx, random.App("dao-app",
			createOrg.GetId()))
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.NoError(t, err)

		// Update app fields.
		createApp.Name = "dao-app-" + random.String(10)
		createApp.DisplayName = "dao-app-" + random.String(10)
		createApp.Email = "dao-app-" + random.Email()
		createApp.PushoverKey = "dao-app-" + random.String(30)
		updateApp, _ := proto.Clone(createApp).(*api.App)

		updateApp, err = globalAppDAO.Update(ctx, updateApp)
		t.Logf("createApp, updateApp, err: %+v, %+v, %v", createApp, updateApp,
			err)
		require.NoError(t, err)
		require.Equal(t, createApp.GetName(), updateApp.GetName())
		require.Equal(t, createApp.GetDisplayName(), updateApp.GetDisplayName())
		require.Equal(t, createApp.GetEmail(), updateApp.GetEmail())
		require.Equal(t, createApp.GetPushoverKey(), updateApp.GetPushoverKey())
		require.True(t, updateApp.GetUpdatedAt().AsTime().After(
			updateApp.GetCreatedAt().AsTime()))
		require.WithinDuration(t, createApp.GetCreatedAt().AsTime(),
			updateApp.GetUpdatedAt().AsTime(), 2*time.Second)

		readApp, err := globalAppDAO.Read(ctx, createApp.GetId(), createApp.GetOrgId())
		t.Logf("readApp, err: %+v, %v", readApp, err)
		require.NoError(t, err)
		require.Equal(t, updateApp, readApp)
	})

	t.Run("Update unknown app", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		updateApp, err := globalAppDAO.Update(ctx, random.App("dao-app",
			createOrg.GetId()))
		t.Logf("updateApp, err: %+v, %v", updateApp, err)
		require.Nil(t, updateApp)
		require.Equal(t, dao.ErrNotFound, err)
	})

	t.Run("Updates are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		createApp, err := globalAppDAO.Create(ctx, random.App("dao-app",
			createOrg.GetId()))
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.NoError(t, err)

		// Update app fields.
		createApp.OrgId = uuid.NewString()
		createApp.Name = "dao-app-" + random.String(10)

		updateApp, err := globalAppDAO.Update(ctx, createApp)
		t.Logf("createApp, updateApp, err: %+v, %+v, %v", createApp, updateApp,
			err)
		require.Nil(t, updateApp)
		require.Equal(t, dao.ErrNotFound, err)
	})

	t.Run("Update app by invalid app", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		createApp, err := globalAppDAO.Create(ctx, random.App("dao-app",
			createOrg.GetId()))
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.NoError(t, err)

		// Update app fields.
		createApp.Name = "dao-app-" + random.String(40)

		updateApp, err := globalAppDAO.Update(ctx, createApp)
		t.Logf("createApp, updateApp, err: %+v, %+v, %v", createApp, updateApp,
			err)
		require.Nil(t, updateApp)
		require.ErrorIs(t, err, dao.ErrInvalidFormat)
	})
}

func TestDelete(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()

	createOrg, err := globalOrgDAO.Create(ctx, random.Org("dao-app"))
	t.Logf("createOrg, err: %+v, %v", createOrg, err)
	require.NoError(t, err)

	t.Run("Delete app by valid ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		createApp, err := globalAppDAO.Create(ctx, random.App("dao-app",
			createOrg.GetId()))
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.NoError(t, err)

		err = globalAppDAO.Delete(ctx, createApp.GetId(), createOrg.GetId())
		t.Logf("err: %v", err)
		require.NoError(t, err)

		t.Run("Read app by deleted ID", func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(t.Context(),
				testTimeout)
			defer cancel()

			readApp, err := globalAppDAO.Read(ctx, createApp.GetId(),
				createOrg.GetId())
			t.Logf("readApp, err: %+v, %v", readApp, err)
			require.Nil(t, readApp)
			require.Equal(t, dao.ErrNotFound, err)
		})
	})

	t.Run("Delete app by unknown ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		err := globalAppDAO.Delete(ctx, uuid.NewString(), createOrg.GetId())
		t.Logf("err: %v", err)
		require.Equal(t, dao.ErrNotFound, err)
	})

	t.Run("Deletes are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		createApp, err := globalAppDAO.Create(ctx, random.App("dao-app",
			createOrg.GetId()))
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.NoError(t, err)

		err = globalAppDAO.Delete(ctx, createApp.GetId(), uuid.NewString())
		t.Logf("err: %v", err)
		require.Equal(t, dao.ErrNotFound, err)
	})
}

func TestList(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()

	createOrg, err := globalOrgDAO.Create(ctx, random.Org("dao-app"))
	t.Logf("createOrg, err: %+v, %v", createOrg, err)
	require.NoError(t, err)

	appIDs := []string{}
	appNames := []string{}
	appEmails := []string{}
	appPushoverKeys := []string{}
	appTSes := []time.Time{}
	for range 3 {
		createApp, err := globalAppDAO.Create(ctx, random.App("dao-app",
			createOrg.GetId()))
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.NoError(t, err)

		appIDs = append(appIDs, createApp.GetId())
		appNames = append(appNames, createApp.GetName())
		appEmails = append(appEmails, createApp.GetEmail())
		appPushoverKeys = append(appPushoverKeys, createApp.GetPushoverKey())
		appTSes = append(appTSes, createApp.GetCreatedAt().AsTime())
	}

	t.Run("List apps by valid org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		listApps, listCount, err := globalAppDAO.List(ctx, createOrg.GetId(),
			time.Time{}, "", 0)
		t.Logf("listApps, listCount, err: %+v, %v, %v", listApps, listCount,
			err)
		require.NoError(t, err)
		require.Len(t, listApps, 3)
		require.Equal(t, int32(3), listCount)

		var found bool
		for _, app := range listApps {
			if app.GetId() == appIDs[len(appIDs)-1] &&
				app.GetName() == appNames[len(appNames)-1] &&
				app.GetEmail() == appEmails[len(appEmails)-1] &&
				app.GetPushoverKey() == appPushoverKeys[len(appPushoverKeys)-1] {
				found = true
			}
		}
		require.True(t, found)
	})

	t.Run("List apps by valid org ID with pagination", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		listApps, listCount, err := globalAppDAO.List(ctx, createOrg.GetId(),
			appTSes[0], appIDs[0], 5)
		t.Logf("listApps, listCount, err: %+v, %v, %v", listApps, listCount,
			err)
		require.NoError(t, err)
		require.Len(t, listApps, 2)
		require.Equal(t, int32(3), listCount)

		var found bool
		for _, app := range listApps {
			if app.GetId() == appIDs[len(appIDs)-1] &&
				app.GetName() == appNames[len(appNames)-1] &&
				app.GetEmail() == appEmails[len(appEmails)-1] &&
				app.GetPushoverKey() == appPushoverKeys[len(appPushoverKeys)-1] {
				found = true
			}
		}
		require.True(t, found)
	})

	t.Run("List apps by valid org ID with limit", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		listApps, listCount, err := globalAppDAO.List(ctx, createOrg.GetId(),
			time.Time{}, "", 1)
		t.Logf("listApps, listCount, err: %+v, %v, %v", listApps, listCount,
			err)
		require.NoError(t, err)
		require.Len(t, listApps, 1)
		require.Equal(t, int32(3), listCount)
	})

	t.Run("Lists are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		listApps, listCount, err := globalAppDAO.List(ctx, uuid.NewString(),
			time.Time{}, "", 0)
		t.Logf("listApps, listCount, err: %+v, %v, %v", listApps, listCount,
			err)
		require.NoError(t, err)
		require.Empty(t, listApps)
		require.Equal(t, int32(0), listCount)
	})

	t.Run("List apps by invalid org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()

		listApps, listCount, err := globalAppDAO.List(ctx, random.String(10),
			time.Time{}, "", 0)
		t.Logf("listApps, listCount, err: %+v, %v, %v", listApps, listCount,
			err)
		require.Nil(t, listApps)
		require.Equal(t, int32(0), listCount)
		require.ErrorIs(t, err, dao.ErrInvalidFormat)
	})
}
