package service

//go:generate mockgen -source user.go -destination mock_userer_test.go -package service

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/mennanov/fmutils"
	"github.com/ownmfa/hermes/internal/hermes-api/session"
	"github.com/ownmfa/hermes/pkg/crypto"
	"github.com/ownmfa/hermes/pkg/hlog"
	"github.com/ownmfa/proto/go/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Userer defines the methods provided by a user.DAO.
type Userer interface {
	Create(ctx context.Context, user *api.User) (*api.User, error)
	Read(ctx context.Context, userID, orgID string) (*api.User, error)
	ReadByEmail(ctx context.Context, email, orgName string) (*api.User, []byte,
		error)
	Update(ctx context.Context, user *api.User) (*api.User, error)
	UpdatePassword(ctx context.Context, userID, orgID string,
		passHash []byte) error
	Delete(ctx context.Context, userID, orgID string) error
	List(ctx context.Context, orgID string, lBoundTS time.Time, prevID string,
		limit int32) ([]*api.User, int32, error)
}

// User service contains functions to query and modify users.
type User struct {
	api.UnimplementedUserServiceServer

	userDAO Userer
}

// NewUser instantiates and returns a new User service.
func NewUser(userDAO Userer) *User {
	return &User{
		userDAO: userDAO,
	}
}

// CreateUser creates a user.
func (u *User) CreateUser(ctx context.Context, req *api.CreateUserRequest) (
	*api.User, error,
) {
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < api.Role_ADMIN {
		return nil, errPerm(api.Role_ADMIN)
	}

	// Only system admins can elevate to system admin.
	if sess.Role < api.Role_SYS_ADMIN &&
		req.GetUser().GetRole() == api.Role_SYS_ADMIN {
		return nil, status.Error(codes.PermissionDenied,
			"permission denied, role modification not allowed")
	}

	req.User.OrgId = sess.OrgID

	user, err := u.userDAO.Create(ctx, req.GetUser())
	if err != nil {
		return nil, errToStatus(err)
	}

	if err := grpc.SetHeader(ctx, metadata.Pairs(StatusCodeKey,
		strconv.Itoa(http.StatusCreated))); err != nil {
		logger := hlog.FromContext(ctx)
		logger.Errorf("CreateUser grpc.SetHeader: %v", err)
	}

	return user, nil
}

// GetUser retrieves a user by ID.
func (u *User) GetUser(ctx context.Context, req *api.GetUserRequest) (
	*api.User, error,
) {
	sess, ok := session.FromContext(ctx)
	if !ok || (sess.Role < api.Role_ADMIN && req.GetId() != sess.UserID) {
		return nil, errPerm(api.Role_ADMIN)
	}

	user, err := u.userDAO.Read(ctx, req.GetId(), sess.OrgID)
	if err != nil {
		return nil, errToStatus(err)
	}

	return user, nil
}

// UpdateUser updates a user. Update actions validate after merge to support
// partial updates.
func (u *User) UpdateUser(ctx context.Context, req *api.UpdateUserRequest) (
	*api.User, error,
) {
	sess, ok := session.FromContext(ctx)
	if !ok {
		return nil, errPerm(api.Role_ADMIN)
	}

	if req.GetUser() == nil {
		return nil, status.Error(codes.InvalidArgument,
			req.Validate().Error())
	}
	req.User.OrgId = sess.OrgID

	// Non-admins can only update their own user.
	if sess.Role < api.Role_ADMIN && req.GetUser().GetId() != sess.UserID {
		return nil, errPerm(api.Role_ADMIN)
	}

	// Only admins can update roles, and only system admins can elevate to
	// system admin.
	if (sess.Role < api.Role_ADMIN && req.GetUser().GetRole() != sess.Role) ||
		(sess.Role < api.Role_SYS_ADMIN &&
			req.GetUser().GetRole() == api.Role_SYS_ADMIN) {
		return nil, status.Error(codes.PermissionDenied,
			"permission denied, role modification not allowed")
	}

	// Perform partial update if directed.
	if len(req.GetUpdateMask().GetPaths()) > 0 {
		// Normalize and validate field mask.
		req.GetUpdateMask().Normalize()
		if !req.GetUpdateMask().IsValid(req.GetUser()) {
			return nil, status.Error(codes.InvalidArgument,
				"invalid field mask")
		}

		user, err := u.userDAO.Read(ctx, req.GetUser().GetId(), sess.OrgID)
		if err != nil {
			return nil, errToStatus(err)
		}

		fmutils.Filter(req.GetUser(), req.GetUpdateMask().GetPaths())
		proto.Merge(user, req.GetUser())
		req.User = user
	}

	// Validate after merge to support partial updates.
	if err := req.Validate(); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	user, err := u.userDAO.Update(ctx, req.GetUser())
	if err != nil {
		return nil, errToStatus(err)
	}

	return user, nil
}

// UpdateUserPassword updates a user's password by ID.
func (u *User) UpdateUserPassword(
	ctx context.Context, req *api.UpdateUserPasswordRequest,
) (*emptypb.Empty, error) {
	sess, ok := session.FromContext(ctx)
	if !ok || (sess.Role < api.Role_ADMIN && req.GetId() != sess.UserID) {
		return nil, errPerm(api.Role_ADMIN)
	}

	if err := crypto.CheckPass(req.GetPassword()); err != nil {
		return nil, errToStatus(err)
	}

	hash, err := crypto.HashPass(req.GetPassword())
	if err != nil {
		logger := hlog.FromContext(ctx)
		logger.Errorf("UpdateUserPassword crypto.HashPass: %v", err)

		return nil, errToStatus(crypto.ErrWeakPass)
	}

	if err := u.userDAO.UpdatePassword(ctx, req.GetId(), sess.OrgID,
		hash); err != nil {
		return nil, errToStatus(err)
	}

	return &emptypb.Empty{}, nil
}

// DeleteUser deletes a user by ID.
func (u *User) DeleteUser(ctx context.Context, req *api.DeleteUserRequest) (
	*emptypb.Empty, error,
) {
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < api.Role_ADMIN {
		return nil, errPerm(api.Role_ADMIN)
	}

	if err := u.userDAO.Delete(ctx, req.GetId(), sess.OrgID); err != nil {
		return nil, errToStatus(err)
	}

	if err := grpc.SetHeader(ctx, metadata.Pairs(StatusCodeKey,
		strconv.Itoa(http.StatusNoContent))); err != nil {
		logger := hlog.FromContext(ctx)
		logger.Errorf("DeleteUser grpc.SetHeader: %v", err)
	}

	return &emptypb.Empty{}, nil
}

// ListUsers retrieves all users.
func (u *User) ListUsers(ctx context.Context, req *api.ListUsersRequest) (
	*api.ListUsersResponse, error,
) {
	sess, ok := session.FromContext(ctx)
	if !ok {
		return nil, errPerm(api.Role_ADMIN)
	}

	// If the user does not have sufficient role, return only their user. Will
	// not be found for API key tokens.
	if sess.Role < api.Role_ADMIN && sess.UserID == "" {
		return &api.ListUsersResponse{}, nil
	}

	if sess.Role < api.Role_ADMIN {
		user, err := u.userDAO.Read(ctx, sess.UserID, sess.OrgID)
		if err != nil {
			return nil, errToStatus(err)
		}

		return &api.ListUsersResponse{
			Users:     []*api.User{user},
			TotalSize: 1,
		}, nil
	}

	if req.GetPageSize() == 0 {
		req.PageSize = defaultPageSize
	}

	lBoundTS, prevID, err := session.ParsePageToken(req.GetPageToken())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid page token")
	}

	// Retrieve PageSize+1 entries to find last page.
	users, count, err := u.userDAO.List(ctx, sess.OrgID, lBoundTS, prevID,
		req.GetPageSize()+1)
	if err != nil {
		return nil, errToStatus(err)
	}

	resp := &api.ListUsersResponse{Users: users, TotalSize: count}

	// Populate next page token.
	if len(users) == int(req.GetPageSize()+1) {
		resp.Users = users[:len(users)-1]

		if resp.NextPageToken, err = session.GeneratePageToken(
			users[len(users)-2].GetCreatedAt().AsTime(),
			users[len(users)-2].GetId()); err != nil {
			// GeneratePageToken should not error based on a DB-derived UUID.
			// Log the error and include the usable empty token.
			logger := hlog.FromContext(ctx)
			logger.Errorf("ListUsers session.GeneratePageToken user, err: "+
				"%+v, %v", users[len(users)-2], err)
		}
	}

	return resp, nil
}
