package interceptor

import (
	"context"
	"strings"

	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/hermes/internal/hermes-api/key"
	"github.com/ownmfa/hermes/internal/hermes-api/service"
	"github.com/ownmfa/hermes/internal/hermes-api/session"
	"github.com/ownmfa/hermes/pkg/cache"
	"github.com/ownmfa/hermes/pkg/hlog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Auth performs authentication and authorization via web token, and implements
// the grpc.UnaryServerInterceptor type signature.
func Auth(
	skipPaths map[string]struct{}, pwtKey []byte, cache cache.Cacher,
	orgDAO service.Orger,
) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context, req interface{}, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if _, ok := skipPaths[info.FullMethod]; ok {
			return handler(ctx, req)
		}

		// Retrieve token from 'Authorization: Bearer ...' header.
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "unauthorized")
		}

		auth := md["authorization"]
		if len(auth) < 1 {
			return nil, status.Error(codes.Unauthenticated, "unauthorized")
		}

		if !strings.HasPrefix(auth[0], "Bearer ") {
			return nil, status.Error(codes.Unauthenticated, "unauthorized")
		}

		// Validate token.
		token := strings.TrimPrefix(auth[0], "Bearer ")
		sess, err := session.ValidateWebToken(pwtKey, token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "unauthorized")
		}

		// Check for disabled API key.
		if sess.KeyID != "" {
			if ok, _, err := cache.Get(ctx, key.Disabled(sess.OrgID,
				sess.KeyID)); ok || err != nil {
				return nil, status.Error(codes.Unauthenticated, "unauthorized")
			}
		}

		// Check for disabled organization.
		org, err := orgDAO.Read(ctx, sess.OrgID)
		if err != nil || org.Status == api.Status_DISABLED {
			return nil, status.Error(codes.Unauthenticated, "unauthorized")
		}
		sess.OrgPlan = org.Plan

		// Add logging fields.
		logger := hlog.FromContext(ctx)
		if sess.UserID != "" {
			logger.Logger = logger.WithField("userID", sess.UserID)
		} else {
			logger.Logger = logger.WithField("keyID", sess.KeyID)
		}
		logger.Logger = logger.WithField("orgID", sess.OrgID)
		logger.Logger = logger.WithField("traceID", sess.TraceID.String())

		ctx = session.NewContext(ctx, sess)

		return handler(ctx, req)
	}
}
