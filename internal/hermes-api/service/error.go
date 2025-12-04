// Package service provides functions that implement gRPC service interfaces.
package service

import (
	"errors"
	"fmt"

	"github.com/ownmfa/hermes/pkg/auth"
	"github.com/ownmfa/hermes/pkg/dao"
	"github.com/ownmfa/hermes/pkg/hlog"
	"github.com/ownmfa/hermes/pkg/notify"
	"github.com/ownmfa/hermes/pkg/oath"
	"github.com/ownmfa/proto/go/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Constants used for endpoint behavior.
const (
	StatusCodeKey   = "hermes-status-code"
	defaultPageSize = 50
)

// errToCode maps DAO errors to gRPC error codes.
var errToCode = map[error]codes.Code{
	auth.ErrWeakPass:          codes.InvalidArgument,
	dao.ErrAlreadyExists:      codes.AlreadyExists,
	dao.ErrInvalidFormat:      codes.InvalidArgument,
	dao.ErrNotFound:           codes.NotFound,
	oath.ErrInvalidPasscode:   codes.InvalidArgument,
	notify.ErrInvalidSMS:      codes.InvalidArgument,
	notify.ErrInvalidPushover: codes.InvalidArgument,
	errExpStatus:              codes.FailedPrecondition,
}

// errToStatus maps DAO errors to gRPC status errors. This function is
// idempotent and is safe to call on the same error multiple times.
func errToStatus(err error) error {
	// If err is nil or is already a gRPC status, return it.
	if code := status.Code(err); code != codes.Unknown {
		return err
	}

	for daoErr, code := range errToCode {
		if errors.Is(err, daoErr) {
			return status.Error(code, err.Error())
		}
	}
	hlog.Errorf("errToStatus unmatched error: %#v", err)

	return status.Error(codes.Unknown, err.Error())
}

// errPerm returns a PermissionDenied status due to insufficient role.
func errPerm(role api.Role) error {
	return status.Error(codes.PermissionDenied,
		fmt.Sprintf("permission denied, %s role required", role.String()))
}

// errPlan returns a PermissionDenied status due to insufficient plan.
func errPlan(plan api.Plan) error {
	return status.Error(codes.PermissionDenied,
		fmt.Sprintf("permission denied, %s plan required", plan.String()))
}
