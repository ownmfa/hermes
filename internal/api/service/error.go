// Package service provides functions that implement gRPC service interfaces.
package service

import (
	"errors"
	"fmt"

	"github.com/ownmfa/api/go/common"
	"github.com/ownmfa/hermes/pkg/crypto"
	"github.com/ownmfa/hermes/pkg/dao"
	"github.com/ownmfa/hermes/pkg/hlog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	StatusCodeKey   = "hermes-status-code"
	defaultPageSize = 50
)

// errToCode maps DAO errors to gRPC error codes.
var errToCode = map[error]codes.Code{
	crypto.ErrWeakPass:   codes.InvalidArgument,
	dao.ErrAlreadyExists: codes.AlreadyExists,
	dao.ErrInvalidFormat: codes.InvalidArgument,
	dao.ErrNotFound:      codes.NotFound,
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
func errPerm(role common.Role) error {
	return status.Error(codes.PermissionDenied,
		fmt.Sprintf("permission denied, %s role required", role.String()))
}
