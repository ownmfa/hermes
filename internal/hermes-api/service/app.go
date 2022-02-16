package service

//go:generate mockgen -source app.go -destination mock_apper_test.go -package service

import (
	"context"
	"time"

	"github.com/mennanov/fmutils"
	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/hermes/internal/hermes-api/session"
	"github.com/ownmfa/hermes/pkg/cache"
	"github.com/ownmfa/hermes/pkg/hlog"
	"github.com/ownmfa/hermes/pkg/notify"
	"github.com/ownmfa/hermes/pkg/queue"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Apper defines the methods provided by an app.DAO.
type Apper interface {
	Create(ctx context.Context, app *api.App) (*api.App, error)
	Read(ctx context.Context, appID, orgID string) (*api.App, error)
	Update(ctx context.Context, app *api.App) (*api.App, error)
	Delete(ctx context.Context, appID, orgID string) error
	List(ctx context.Context, orgID string, lBoundTS time.Time, prevID string,
		limit int32) ([]*api.App, int32, error)
}

// AppIdentity service contains functions to query and modify applications and
// identities.
type AppIdentity struct {
	api.UnimplementedAppIdentityServiceServer

	appDAO   Apper
	identDAO Identityer
	evDAO    Eventer
	cache    cache.Cacher

	notify notify.Notifier

	aiQueue     queue.Queuer
	nInPubTopic string
}

// NewAppIdentity instantiates and returns a new AppIdentity service.
func NewAppIdentity(appDAO Apper, identDAO Identityer, evDAO Eventer,
	cache cache.Cacher, notify notify.Notifier, pubQueue queue.Queuer,
	pubTopic string) *AppIdentity {
	return &AppIdentity{
		appDAO:   appDAO,
		identDAO: identDAO,
		evDAO:    evDAO,
		cache:    cache,

		notify: notify,

		aiQueue:     pubQueue,
		nInPubTopic: pubTopic,
	}
}

// CreateApp creates an application.
func (ai *AppIdentity) CreateApp(ctx context.Context,
	req *api.CreateAppRequest) (*api.App, error) {
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < api.Role_ADMIN {
		return nil, errPerm(api.Role_ADMIN)
	}

	req.App.OrgId = sess.OrgID

	app, err := ai.appDAO.Create(ctx, req.App)
	if err != nil {
		return nil, errToStatus(err)
	}

	if err := grpc.SetHeader(ctx, metadata.Pairs(StatusCodeKey,
		"201")); err != nil {
		logger := hlog.FromContext(ctx)
		logger.Errorf("CreateApp grpc.SetHeader: %v", err)
	}

	return app, nil
}

// GetApp retrieves an application by ID.
func (ai *AppIdentity) GetApp(ctx context.Context,
	req *api.GetAppRequest) (*api.App, error) {
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < api.Role_VIEWER {
		return nil, errPerm(api.Role_VIEWER)
	}

	app, err := ai.appDAO.Read(ctx, req.Id, sess.OrgID)
	if err != nil {
		return nil, errToStatus(err)
	}

	return app, nil
}

// UpdateApp updates an application. Update actions validate after merge to
// support partial updates.
func (ai *AppIdentity) UpdateApp(ctx context.Context,
	req *api.UpdateAppRequest) (*api.App, error) {
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < api.Role_ADMIN {
		return nil, errPerm(api.Role_ADMIN)
	}

	if req.App == nil {
		return nil, status.Error(codes.InvalidArgument,
			req.Validate().Error())
	}
	req.App.OrgId = sess.OrgID

	// Perform partial update if directed.
	if req.UpdateMask != nil && len(req.UpdateMask.Paths) > 0 {
		// Normalize and validate field mask.
		req.UpdateMask.Normalize()
		if !req.UpdateMask.IsValid(req.App) {
			return nil, status.Error(codes.InvalidArgument,
				"invalid field mask")
		}

		app, err := ai.appDAO.Read(ctx, req.App.Id, sess.OrgID)
		if err != nil {
			return nil, errToStatus(err)
		}

		fmutils.Filter(req.App, req.UpdateMask.Paths)
		proto.Merge(app, req.App)
		req.App = app
	}

	// Validate after merge to support partial updates.
	if err := req.Validate(); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	app, err := ai.appDAO.Update(ctx, req.App)
	if err != nil {
		return nil, errToStatus(err)
	}

	return app, nil
}

// DeleteApp deletes an application by ID.
func (ai *AppIdentity) DeleteApp(ctx context.Context,
	req *api.DeleteAppRequest) (*emptypb.Empty, error) {
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < api.Role_ADMIN {
		return nil, errPerm(api.Role_ADMIN)
	}

	if err := ai.appDAO.Delete(ctx, req.Id, sess.OrgID); err != nil {
		return nil, errToStatus(err)
	}

	if err := grpc.SetHeader(ctx, metadata.Pairs(StatusCodeKey,
		"204")); err != nil {
		logger := hlog.FromContext(ctx)
		logger.Errorf("DeleteApp grpc.SetHeader: %v", err)
	}

	return &emptypb.Empty{}, nil
}

// ListApps retrieves all applications.
func (ai *AppIdentity) ListApps(ctx context.Context,
	req *api.ListAppsRequest) (*api.ListAppsResponse, error) {
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < api.Role_VIEWER {
		return nil, errPerm(api.Role_VIEWER)
	}

	if req.PageSize == 0 {
		req.PageSize = defaultPageSize
	}

	lBoundTS, prevID, err := session.ParsePageToken(req.PageToken)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid page token")
	}

	// Retrieve PageSize+1 entries to find last page.
	apps, count, err := ai.appDAO.List(ctx, sess.OrgID, lBoundTS, prevID,
		req.PageSize+1)
	if err != nil {
		return nil, errToStatus(err)
	}

	resp := &api.ListAppsResponse{Apps: apps, TotalSize: count}

	// Populate next page token.
	if len(apps) == int(req.PageSize+1) {
		resp.Apps = apps[:len(apps)-1]

		if resp.NextPageToken, err = session.GeneratePageToken(
			apps[len(apps)-2].CreatedAt.AsTime(),
			apps[len(apps)-2].Id); err != nil {
			// GeneratePageToken should not error based on a DB-derived UUID.
			// Log the error and include the usable empty token.
			logger := hlog.FromContext(ctx)
			logger.Errorf("ListApps session.GeneratePageToken app, err: "+
				"%+v, %v", apps[len(apps)-2], err)
		}
	}

	return resp, nil
}
