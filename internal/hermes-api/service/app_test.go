//go:build !integration

package service

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ownmfa/hermes/internal/hermes-api/session"
	"github.com/ownmfa/hermes/pkg/dao"
	"github.com/ownmfa/hermes/pkg/test/matcher"
	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/ownmfa/proto/go/api"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func TestCreateApp(t *testing.T) {
	t.Parallel()

	t.Run("Create valid app", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())
		retApp, _ := proto.Clone(app).(*api.App)

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().Create(gomock.Any(), app).Return(retApp, nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: app.GetOrgId(), Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, nil, "")
		createApp, err := aiSvc.CreateApp(ctx, &api.CreateAppRequest{App: app})
		t.Logf("app, createApp, err: %+v, %+v, %v", app, createApp, err)
		require.NoError(t, err)
		require.EqualExportedValues(t, app, createApp)
	})

	t.Run("Create app with invalid session", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		createApp, err := aiSvc.CreateApp(ctx, &api.CreateAppRequest{})
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.Nil(t, createApp)
		require.Equal(t, errPerm(api.Role_ADMIN), err)
	})

	t.Run("Create app with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: api.Role_VIEWER,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		createApp, err := aiSvc.CreateApp(ctx, &api.CreateAppRequest{})
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.Nil(t, createApp)
		require.Equal(t, errPerm(api.Role_ADMIN), err)
	})

	t.Run("Create invalid app", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())
		app.Name = random.String(41)

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().Create(gomock.Any(), app).Return(nil,
			dao.ErrInvalidFormat).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: app.GetOrgId(), Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, nil, "")
		createApp, err := aiSvc.CreateApp(ctx, &api.CreateAppRequest{App: app})
		t.Logf("app, createApp, err: %+v, %+v, %v", app, createApp, err)
		require.Nil(t, createApp)
		require.Equal(t, status.Error(codes.InvalidArgument, "invalid format"),
			err)
	})
}

func TestGetApp(t *testing.T) {
	t.Parallel()

	t.Run("Get app by valid ID", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())
		retApp, _ := proto.Clone(app).(*api.App)

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().Read(gomock.Any(), app.GetId(), app.GetOrgId()).Return(retApp,
			nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: app.GetOrgId(), Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, nil, "")
		getApp, err := aiSvc.GetApp(ctx, &api.GetAppRequest{Id: app.GetId()})
		t.Logf("app, getApp, err: %+v, %+v, %v", app, getApp, err)
		require.NoError(t, err)
		require.EqualExportedValues(t, app, getApp)
	})

	t.Run("Get app with invalid session", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		getApp, err := aiSvc.GetApp(ctx, &api.GetAppRequest{})
		t.Logf("getApp, err: %+v, %v", getApp, err)
		require.Nil(t, getApp)
		require.Equal(t, errPerm(api.Role_VIEWER), err)
	})

	t.Run("Get app with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: api.Role_ROLE_UNSPECIFIED,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		getApp, err := aiSvc.GetApp(ctx, &api.GetAppRequest{})
		t.Logf("getApp, err: %+v, %v", getApp, err)
		require.Nil(t, getApp)
		require.Equal(t, errPerm(api.Role_VIEWER), err)
	})

	t.Run("Get app by unknown ID", func(t *testing.T) {
		t.Parallel()

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().Read(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, nil, "")
		getApp, err := aiSvc.GetApp(ctx,
			&api.GetAppRequest{Id: uuid.NewString()})
		t.Logf("getApp, err: %+v, %v", getApp, err)
		require.Nil(t, getApp)
		require.Equal(t, status.Error(codes.NotFound, "object not found"), err)
	})
}

func TestUpdateApp(t *testing.T) {
	t.Parallel()

	t.Run("Update app by valid app", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())
		retApp, _ := proto.Clone(app).(*api.App)

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().Update(gomock.Any(), app).Return(retApp, nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: app.GetOrgId(), Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, nil, "")
		updateApp, err := aiSvc.UpdateApp(ctx, &api.UpdateAppRequest{
			App: app,
		})
		t.Logf("app, updateApp, err: %+v, %+v, %v", app, updateApp, err)
		require.NoError(t, err)
		require.EqualExportedValues(t, app, updateApp)
	})

	t.Run("Partial update app by valid app", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())
		retApp, _ := proto.Clone(app).(*api.App)
		part := &api.App{
			Id: app.GetId(), Name: random.String(10), DisplayName: random.String(10),
			PushoverKey: random.String(30),
		}
		merged := &api.App{
			Id: app.GetId(), OrgId: app.GetOrgId(), Name: part.GetName(),
			DisplayName: part.GetDisplayName(), Email: app.GetEmail(),
			PushoverKey: part.GetPushoverKey(), SubjectTemplate: app.GetSubjectTemplate(),
			TextBodyTemplate: app.GetTextBodyTemplate(),
			HtmlBodyTemplate: app.GetHtmlBodyTemplate(),
		}
		retMerged, _ := proto.Clone(merged).(*api.App)

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().Read(gomock.Any(), app.GetId(), app.GetOrgId()).Return(retApp,
			nil).Times(1)
		apper.EXPECT().Update(gomock.Any(), matcher.NewProtoMatcher(merged)).
			Return(retMerged, nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: app.GetOrgId(), Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, nil, "")
		updateApp, err := aiSvc.UpdateApp(ctx, &api.UpdateAppRequest{
			App: part, UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"name", "display_name", "pushover_key"},
			},
		})
		t.Logf("merged, updateApp, err: %+v, %+v, %v", merged, updateApp, err)
		require.NoError(t, err)
		require.EqualExportedValues(t, merged, updateApp)
	})

	t.Run("Update app with invalid session", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		updateApp, err := aiSvc.UpdateApp(ctx, &api.UpdateAppRequest{})
		t.Logf("updateApp, err: %+v, %v", updateApp, err)
		require.Nil(t, updateApp)
		require.Equal(t, errPerm(api.Role_ADMIN), err)
	})

	t.Run("Update app with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: api.Role_VIEWER,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		updateApp, err := aiSvc.UpdateApp(ctx, &api.UpdateAppRequest{})
		t.Logf("updateApp, err: %+v, %v", updateApp, err)
		require.Nil(t, updateApp)
		require.Equal(t, errPerm(api.Role_ADMIN), err)
	})

	t.Run("Update nil app", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		updateApp, err := aiSvc.UpdateApp(ctx, &api.UpdateAppRequest{App: nil})
		t.Logf("updateApp, err: %+v, %v", updateApp, err)
		require.Nil(t, updateApp)
		require.Equal(t, status.Error(codes.InvalidArgument,
			"invalid UpdateAppRequest.App: value is required"), err)
	})

	t.Run("Partial update invalid field mask", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		updateApp, err := aiSvc.UpdateApp(ctx, &api.UpdateAppRequest{
			App: app, UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"aaa"},
			},
		})
		t.Logf("app, updateApp, err: %+v, %+v, %v", app, updateApp, err)
		require.Nil(t, updateApp)
		require.Equal(t, status.Error(codes.InvalidArgument,
			"invalid field mask"), err)
	})

	t.Run("Partial update app by unknown app", func(t *testing.T) {
		t.Parallel()

		orgID := uuid.NewString()
		part := &api.App{Id: uuid.NewString(), Name: random.String(10)}

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().Read(gomock.Any(), part.GetId(), orgID).
			Return(nil, dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: orgID, Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, nil, "")
		updateApp, err := aiSvc.UpdateApp(ctx, &api.UpdateAppRequest{
			App: part, UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"name"},
			},
		})
		t.Logf("part, updateApp, err: %+v, %+v, %v", part, updateApp, err)
		require.Nil(t, updateApp)
		require.Equal(t, status.Error(codes.NotFound, "object not found"), err)
	})

	t.Run("Update app validation failure", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())
		app.Name = random.String(41)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: app.GetOrgId(), Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		updateApp, err := aiSvc.UpdateApp(ctx, &api.UpdateAppRequest{
			App: app,
		})
		t.Logf("app, updateApp, err: %+v, %+v, %v", app, updateApp, err)
		require.Nil(t, updateApp)
		require.Equal(t, status.Error(codes.InvalidArgument,
			"invalid UpdateAppRequest.App: embedded message failed "+
				"validation | caused by: invalid App.Name: value length "+
				"must be between 5 and 40 runes, inclusive"), err)
	})

	t.Run("Update app by invalid app", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().Update(gomock.Any(), app).Return(nil,
			dao.ErrInvalidFormat).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: app.GetOrgId(), Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, nil, "")
		updateApp, err := aiSvc.UpdateApp(ctx, &api.UpdateAppRequest{
			App: app,
		})
		t.Logf("app, updateApp, err: %+v, %+v, %v", app, updateApp, err)
		require.Nil(t, updateApp)
		require.Equal(t, status.Error(codes.InvalidArgument, "invalid format"),
			err)
	})
}

func TestDeleteApp(t *testing.T) {
	t.Parallel()

	t.Run("Delete app by valid ID", func(t *testing.T) {
		t.Parallel()

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().Delete(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, nil, "")
		_, err := aiSvc.DeleteApp(ctx,
			&api.DeleteAppRequest{Id: uuid.NewString()})
		t.Logf("err: %v", err)
		require.NoError(t, err)
	})

	t.Run("Delete app with invalid session", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		_, err := aiSvc.DeleteApp(ctx, &api.DeleteAppRequest{})
		t.Logf("err: %v", err)
		require.Equal(t, errPerm(api.Role_ADMIN), err)
	})

	t.Run("Delete app with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: api.Role_VIEWER,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		_, err := aiSvc.DeleteApp(ctx, &api.DeleteAppRequest{})
		t.Logf("err: %v", err)
		require.Equal(t, errPerm(api.Role_ADMIN), err)
	})

	t.Run("Delete app by unknown ID", func(t *testing.T) {
		t.Parallel()

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().Delete(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, nil, "")
		_, err := aiSvc.DeleteApp(ctx,
			&api.DeleteAppRequest{Id: uuid.NewString()})
		t.Logf("err: %v", err)
		require.Equal(t, status.Error(codes.NotFound, "object not found"), err)
	})
}

func TestListApps(t *testing.T) {
	t.Parallel()

	t.Run("List apps by valid org ID", func(t *testing.T) {
		t.Parallel()

		orgID := uuid.NewString()

		apps := []*api.App{
			random.App("api-app", uuid.NewString()),
			random.App("api-app", uuid.NewString()),
			random.App("api-app", uuid.NewString()),
		}

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().List(gomock.Any(), orgID, time.Time{}, "", int32(51)).
			Return(apps, int32(3), nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: orgID, Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, nil, "")
		listApps, err := aiSvc.ListApps(ctx, &api.ListAppsRequest{})
		t.Logf("listApps, err: %+v, %v", listApps, err)
		require.NoError(t, err)
		require.Equal(t, int32(3), listApps.GetTotalSize())
		require.EqualExportedValues(t,
			&api.ListAppsResponse{Apps: apps, TotalSize: 3}, listApps)
	})

	t.Run("List apps by valid org ID with next page", func(t *testing.T) {
		t.Parallel()

		orgID := uuid.NewString()

		apps := []*api.App{
			random.App("api-app", uuid.NewString()),
			random.App("api-app", uuid.NewString()),
			random.App("api-app", uuid.NewString()),
		}

		next, err := session.GeneratePageToken(apps[1].GetCreatedAt().AsTime(),
			apps[1].GetId())
		require.NoError(t, err)

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().List(gomock.Any(), orgID, time.Time{}, "", int32(3)).
			Return(apps, int32(3), nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: orgID, Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, nil, "")
		listApps, err := aiSvc.ListApps(ctx, &api.ListAppsRequest{PageSize: 2})
		t.Logf("listApps, err: %+v, %v", listApps, err)
		require.NoError(t, err)
		require.Equal(t, int32(3), listApps.GetTotalSize())
		require.EqualExportedValues(t, &api.ListAppsResponse{
			Apps: apps[:2], NextPageToken: next, TotalSize: 3,
		}, listApps)
	})

	t.Run("List apps with invalid session", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		listApps, err := aiSvc.ListApps(ctx, &api.ListAppsRequest{})
		t.Logf("listApps, err: %+v, %v", listApps, err)
		require.Nil(t, listApps)
		require.Equal(t, errPerm(api.Role_VIEWER), err)
	})

	t.Run("List apps with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: api.Role_ROLE_UNSPECIFIED,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		listApps, err := aiSvc.ListApps(ctx, &api.ListAppsRequest{})
		t.Logf("listApps, err: %+v, %v", listApps, err)
		require.Nil(t, listApps)
		require.Equal(t, errPerm(api.Role_VIEWER), err)
	})

	t.Run("List apps by invalid page token", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		listApps, err := aiSvc.ListApps(ctx,
			&api.ListAppsRequest{PageToken: badUUID})
		t.Logf("listApps, err: %+v, %v", listApps, err)
		require.Nil(t, listApps)
		require.Equal(t, status.Error(codes.InvalidArgument,
			"invalid page token"), err)
	})

	t.Run("List apps by invalid org ID", func(t *testing.T) {
		t.Parallel()

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().List(gomock.Any(), "aaa", gomock.Any(), gomock.Any(),
			gomock.Any()).Return(nil, int32(0), dao.ErrInvalidFormat).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: "aaa", Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, nil, "")
		listApps, err := aiSvc.ListApps(ctx, &api.ListAppsRequest{})
		t.Logf("listApps, err: %+v, %v", listApps, err)
		require.Nil(t, listApps)
		require.Equal(t, status.Error(codes.InvalidArgument, "invalid format"),
			err)
	})

	t.Run("List apps with generation failure", func(t *testing.T) {
		t.Parallel()

		orgID := uuid.NewString()

		apps := []*api.App{
			random.App("api-app", uuid.NewString()),
			random.App("api-app", uuid.NewString()),
			random.App("api-app", uuid.NewString()),
		}
		apps[1].Id = badUUID

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().List(gomock.Any(), orgID, time.Time{}, "", int32(3)).
			Return(apps, int32(3), nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: orgID, Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, nil, "")
		listApps, err := aiSvc.ListApps(ctx, &api.ListAppsRequest{PageSize: 2})
		t.Logf("listApps, err: %+v, %v", listApps, err)
		require.NoError(t, err)
		require.Equal(t, int32(3), listApps.GetTotalSize())
		require.EqualExportedValues(t,
			&api.ListAppsResponse{Apps: apps[:2], TotalSize: 3}, listApps)
	})
}
