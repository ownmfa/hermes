package service

//go:generate mockgen -source event.go -destination mock_eventer_test.go -package service

import (
	"context"
	"time"

	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/api/go/common"
	"github.com/ownmfa/hermes/internal/hermes-api/session"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Eventer defines the methods provided by a event.DAO.
type Eventer interface {
	Create(ctx context.Context, event *api.Event) error
	List(ctx context.Context, orgID, identityID string, end,
		start time.Time) ([]*api.Event, error)
	Latest(ctx context.Context, orgID, appID, identityID string) ([]*api.Event,
		error)
}

// Event service contains functions to query events.
type Event struct {
	api.UnimplementedEventServiceServer

	evDAO Eventer
}

// NewEvent instantiates and returns a new Event service.
func NewEvent(evDAO Eventer) *Event {
	return &Event{
		evDAO: evDAO,
	}
}

// ListEvents retrieves all events for an identity in an [end, start) time
// range, in descending timestamp order.
func (e *Event) ListEvents(ctx context.Context,
	req *api.ListEventsRequest) (*api.ListEventsResponse, error) {
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < common.Role_VIEWER {
		return nil, errPerm(common.Role_VIEWER)
	}

	end := time.Now().UTC()
	if req.EndTime != nil {
		end = req.EndTime.AsTime().UTC()
	}

	start := end.Add(-24 * time.Hour)
	if req.StartTime != nil && req.StartTime.AsTime().UTC().Before(end) {
		start = req.StartTime.AsTime().UTC()
	}

	if end.Sub(start) > 90*24*time.Hour {
		return nil, status.Error(codes.InvalidArgument,
			"maximum time range exceeded")
	}

	events, err := e.evDAO.List(ctx, sess.OrgID, req.IdentityId, end, start)
	if err != nil {
		return nil, errToStatus(err)
	}

	return &api.ListEventsResponse{Events: events}, nil
}

// LatestEvents retrieves the latest event for each of an organization's
// identities.
func (e *Event) LatestEvents(ctx context.Context,
	req *api.LatestEventsRequest) (*api.LatestEventsResponse, error) {
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < common.Role_VIEWER {
		return nil, errPerm(common.Role_VIEWER)
	}

	events, err := e.evDAO.Latest(ctx, sess.OrgID, req.AppId, req.IdentityId)
	if err != nil {
		return nil, errToStatus(err)
	}

	return &api.LatestEventsResponse{Events: events}, nil
}