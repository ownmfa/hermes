//go:build !integration

package interceptor

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/hermes/internal/hermes-api/service"
	"github.com/ownmfa/hermes/internal/hermes-api/session"
	"github.com/ownmfa/hermes/pkg/cache"
	"github.com/ownmfa/hermes/pkg/consterr"
	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/stretchr/testify/require"
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

	keyToken, err := session.GenerateKeyToken(key, uuid.NewString(), user.OrgId,
		user.Role)
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
			&api.Org{Id: user.OrgId, Status: api.Status_ACTIVE}, nil, 1, nil,
		},
		{
			[]string{"authorization", "Bearer " + keyToken},
			nil, nil,
			&grpc.UnaryServerInfo{FullMethod: random.String(10)}, false, nil, 1,
			&api.Org{Id: user.OrgId, Status: api.Status_ACTIVE}, nil, 1, nil,
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
			&api.Org{Id: user.OrgId, Status: api.Status_ACTIVE}, errTestFunc, 1,
			status.Error(codes.Unauthenticated, "unauthorized"),
		},
		{
			[]string{"authorization", "Bearer " + webToken},
			errTestFunc, nil,
			&grpc.UnaryServerInfo{FullMethod: random.String(10)}, false, nil, 0,
			&api.Org{Id: user.OrgId, Status: api.Status_DISABLED}, nil, 1,
			status.Error(codes.Unauthenticated, "unauthorized"),
		},
	}

	for _, test := range tests {
		lTest := test

		t.Run(fmt.Sprintf("Can log %+v", lTest), func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			cacher := cache.NewMockCacher(ctrl)
			cacher.EXPECT().Get(gomock.Any(), gomock.Any()).
				Return(lTest.inpCache, "", lTest.inpCacheErr).
				Times(lTest.inpCacheTimes)
			orger := service.NewMockOrger(ctrl)
			orger.EXPECT().Read(gomock.Any(), lTest.inpOrg.Id).
				Return(lTest.inpOrg, lTest.inpOrgErr).Times(lTest.inpOrgTimes)

			ctx, cancel := context.WithTimeout(context.Background(),
				testTimeout)
			defer cancel()
			if lTest.inpMD != nil {
				ctx = metadata.NewIncomingContext(ctx,
					metadata.Pairs(lTest.inpMD...))
			}

			handler := func(ctx context.Context, req interface{}) (interface{},
				error) {
				return req, lTest.inpHandlerErr
			}

			res, err := Auth(lTest.inpSkipPaths, key, cacher, orger)(ctx, nil,
				lTest.inpInfo, handler)
			t.Logf("res, err: %v, %v", res, err)
			require.Nil(t, res)
			require.Equal(t, lTest.err, err)
		})
	}
}
