//go:build !integration

package interceptor

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/ownmfa/hermes/internal/hermes-api/service"
	"github.com/ownmfa/hermes/internal/hermes-api/session"
	"github.com/ownmfa/hermes/pkg/cache"
	"github.com/ownmfa/hermes/pkg/consterr"
	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/ownmfa/proto/go/api"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const errTestFunc consterr.Error = "interceptor: test function error"

func TestAuth(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	user := random.User("auth", uuid.NewString())
	webToken, _, err := session.GenerateWebToken(key, user)
	t.Logf("webToken, err: %v, %v", webToken, err)
	require.NoError(t, err)

	keyToken, err := session.GenerateKeyToken(key, uuid.NewString(), user.GetOrgId(),
		user.GetRole())
	t.Logf("keyToken, err: %v, %v", keyToken, err)
	require.NoError(t, err)

	skipPath := random.String(10)

	tests := []struct {
		inpMD         []string
		inpHandlerErr error
		inpSkipPaths  map[string]struct{}
		inpInfo       *grpc.UnaryServerInfo
		inpCache      bool
		inpCacheErr   error
		inpCacheTimes int
		inpOrg        *api.Org
		inpOrgErr     error
		inpOrgTimes   int
		err           error
	}{
		{
			[]string{"authorization", "Bearer " + webToken},
			nil, nil,
			&grpc.UnaryServerInfo{FullMethod: random.String(10)}, false, nil, 0,
			&api.Org{Id: user.GetOrgId(), Status: api.Status_ACTIVE}, nil, 1, nil,
		},
		{
			[]string{"authorization", "Bearer " + keyToken},
			nil, nil,
			&grpc.UnaryServerInfo{FullMethod: random.String(10)}, false, nil, 1,
			&api.Org{Id: user.GetOrgId(), Status: api.Status_ACTIVE}, nil, 1, nil,
		},
		{
			nil, errTestFunc,
			map[string]struct{}{skipPath: {}},
			&grpc.UnaryServerInfo{FullMethod: skipPath}, false, nil, 0,
			&api.Org{}, nil, 0, errTestFunc,
		},
		{
			nil, errTestFunc, nil, &grpc.UnaryServerInfo{
				FullMethod: random.String(10),
			}, false, nil, 0, &api.Org{}, nil, 0,
			status.Error(codes.Unauthenticated, "unauthorized"),
		},
		{
			[]string{}, errTestFunc, nil, &grpc.UnaryServerInfo{
				FullMethod: random.String(10),
			}, false, nil, 0, &api.Org{}, nil, 0, status.Error(
				codes.Unauthenticated, "unauthorized"),
		},
		{
			[]string{"authorization", "NoBearer " + webToken},
			errTestFunc, nil,
			&grpc.UnaryServerInfo{FullMethod: random.String(10)}, false, nil, 0,
			&api.Org{}, nil, 0, status.Error(codes.Unauthenticated,
				"unauthorized"),
		},
		{
			[]string{"authorization", "Bearer ..."},
			errTestFunc, nil,
			&grpc.UnaryServerInfo{FullMethod: random.String(10)}, false, nil, 0,
			&api.Org{}, nil, 0, status.Error(codes.Unauthenticated,
				"unauthorized"),
		},
		{
			[]string{"authorization", "Bearer " + keyToken},
			errTestFunc, nil,
			&grpc.UnaryServerInfo{FullMethod: random.String(10)}, true, nil, 1,
			&api.Org{}, nil, 0, status.Error(codes.Unauthenticated,
				"unauthorized"),
		},
		{
			[]string{"authorization", "Bearer " + webToken},
			errTestFunc, nil,
			&grpc.UnaryServerInfo{FullMethod: random.String(10)}, false, nil, 0,
			&api.Org{Id: user.GetOrgId(), Status: api.Status_ACTIVE}, errTestFunc, 1,
			status.Error(codes.Unauthenticated, "unauthorized"),
		},
		{
			[]string{"authorization", "Bearer " + webToken},
			errTestFunc, nil,
			&grpc.UnaryServerInfo{FullMethod: random.String(10)}, false, nil, 0,
			&api.Org{Id: user.GetOrgId(), Status: api.Status_DISABLED}, nil, 1,
			status.Error(codes.Unauthenticated, "unauthorized"),
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Can log %+v", test), func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			cacher := cache.NewMockCacher(ctrl)
			cacher.EXPECT().Get(gomock.Any(), gomock.Any()).
				Return(test.inpCache, "", test.inpCacheErr).
				Times(test.inpCacheTimes)
			orger := service.NewMockOrger(ctrl)
			orger.EXPECT().Read(gomock.Any(), test.inpOrg.GetId()).
				Return(test.inpOrg, test.inpOrgErr).Times(test.inpOrgTimes)

			ctx, cancel := context.WithTimeout(t.Context(),
				testTimeout)
			defer cancel()
			if test.inpMD != nil {
				ctx = metadata.NewIncomingContext(ctx,
					metadata.Pairs(test.inpMD...))
			}

			handler := func(_ context.Context, req interface{}) (
				interface{}, error,
			) {
				return req, test.inpHandlerErr
			}

			res, err := Auth(test.inpSkipPaths, key, cacher, orger)(ctx, nil,
				test.inpInfo, handler)
			t.Logf("res, err: %v, %v", res, err)
			require.Nil(t, res)
			require.Equal(t, test.err, err)
		})
	}
}
