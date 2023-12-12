//go:build !unit

package test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	iapi "github.com/ownmfa/hermes/internal/hermes-api/api"
	"github.com/ownmfa/hermes/internal/hermes-api/session"
	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/ownmfa/proto/go/api"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestLogin(t *testing.T) {
	t.Parallel()

	org := random.Org("api-session")
	org.Status = api.Status_ACTIVE

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	createOrg, err := globalOrgDAO.Create(ctx, org)
	t.Logf("createOrg, err: %+v, %v", createOrg, err)
	require.NoError(t, err)

	user := random.User("api-session", createOrg.GetId())
	user.Role = api.Role_ADMIN
	user.Status = api.Status_ACTIVE
	createUser, err := globalUserDAO.Create(ctx, user)
	t.Logf("createUser, err: %+v, %v", createUser, err)
	require.NoError(t, err)

	err = globalUserDAO.UpdatePassword(ctx, createUser.GetId(), createOrg.GetId(),
		globalHash)
	t.Logf("err: %v", err)
	require.NoError(t, err)

	disOrg := random.Org("api-session")
	disOrg.Status = api.Status_ACTIVE
	createDisOrg, err := globalOrgDAO.Create(ctx, disOrg)
	t.Logf("createDisOrg, err: %+v, %v", createDisOrg, err)
	require.NoError(t, err)

	createDisOrgUser, err := globalUserDAO.Create(ctx,
		random.User("api-session", createDisOrg.GetId()))
	t.Logf("createDisOrgUser, err: %+v, %v", createDisOrgUser, err)
	require.NoError(t, err)

	disUser := random.User("api-session", createOrg.GetId())
	disUser.Status = api.Status_DISABLED
	createDisUser, err := globalUserDAO.Create(ctx, disUser)
	t.Logf("createDisUser, err: %+v, %v", createDisUser, err)
	require.NoError(t, err)

	err = globalUserDAO.UpdatePassword(ctx, createDisUser.GetId(), createOrg.GetId(),
		globalHash)
	t.Logf("err: %v", err)
	require.NoError(t, err)

	unspecUser := random.User("api-session", createOrg.GetId())
	unspecUser.Role = api.Role_ROLE_UNSPECIFIED
	unspecUser.Status = api.Status_ACTIVE
	createUnspecUser, err := globalUserDAO.Create(ctx, unspecUser)
	t.Logf("createUnspecUser, err: %+v, %v", createUnspecUser, err)
	require.NoError(t, err)

	err = globalUserDAO.UpdatePassword(ctx, createUnspecUser.GetId(), createOrg.GetId(),
		globalHash)
	t.Logf("err: %v", err)
	require.NoError(t, err)

	t.Run("Log in valid user", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		sessCli := api.NewSessionServiceClient(globalNoAuthGRPCConn)
		login, err := sessCli.Login(ctx, &api.LoginRequest{
			Email: createUser.GetEmail(), OrgName: createOrg.GetName(),
			Password: globalPass,
		})
		t.Logf("loginResp, err: %+v, %v", login, err)
		require.NoError(t, err)
		require.Greater(t, len(login.GetToken()), 90)
		require.WithinDuration(t, time.Now().Add(
			session.WebTokenExp*time.Second), login.GetExpiresAt().AsTime(),
			2*time.Second)
	})

	t.Run("Log in disabled org", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		sessCli := api.NewSessionServiceClient(globalNoAuthGRPCConn)
		login, err := sessCli.Login(ctx, &api.LoginRequest{
			Email: createDisOrgUser.GetEmail(), OrgName: createDisOrg.GetName(),
			Password: random.String(10),
		})
		t.Logf("loginResp, err: %+v, %v", login, err)
		require.Nil(t, login)
		require.EqualError(t, err, "rpc error: code = Unauthenticated desc = "+
			"unauthorized")
	})

	t.Run("Log in unknown user", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		sessCli := api.NewSessionServiceClient(globalNoAuthGRPCConn)
		login, err := sessCli.Login(ctx, &api.LoginRequest{
			Email: random.Email(), OrgName: random.String(10),
			Password: random.String(10),
		})
		t.Logf("loginResp, err: %+v, %v", login, err)
		require.Nil(t, login)
		require.EqualError(t, err, "rpc error: code = Unauthenticated desc = "+
			"unauthorized")
	})

	t.Run("Log in wrong password", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		sessCli := api.NewSessionServiceClient(globalNoAuthGRPCConn)
		login, err := sessCli.Login(ctx, &api.LoginRequest{
			Email: createUser.GetEmail(), OrgName: createOrg.GetName(),
			Password: random.String(10),
		})
		t.Logf("loginResp, err: %+v, %v", login, err)
		require.Nil(t, login)
		require.EqualError(t, err, "rpc error: code = Unauthenticated desc = "+
			"unauthorized")
	})

	t.Run("Log in disabled user", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		sessCli := api.NewSessionServiceClient(globalNoAuthGRPCConn)
		login, err := sessCli.Login(ctx, &api.LoginRequest{
			Email: createDisUser.GetEmail(), OrgName: createOrg.GetName(),
			Password: globalPass,
		})
		t.Logf("loginResp, err: %+v, %v", login, err)
		require.Nil(t, login)
		require.EqualError(t, err, "rpc error: code = Unauthenticated desc = "+
			"unauthorized")
	})

	t.Run("Log in unspecified user", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		sessCli := api.NewSessionServiceClient(globalNoAuthGRPCConn)
		login, err := sessCli.Login(ctx, &api.LoginRequest{
			Email: createUnspecUser.GetEmail(), OrgName: createOrg.GetName(),
			Password: globalPass,
		})
		t.Logf("loginResp, err: %+v, %v", login, err)
		require.Nil(t, login)
		require.EqualError(t, err, "rpc error: code = Unauthenticated desc = "+
			"unauthorized")
	})
}

func TestCreateKey(t *testing.T) {
	t.Parallel()

	t.Run("Create valid key", func(t *testing.T) {
		t.Parallel()

		key := random.Key("api-key", uuid.NewString())
		key.Role = api.Role_AUTHENTICATOR

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		sessCli := api.NewSessionServiceClient(globalAdminGRPCConn)
		createKey, err := sessCli.CreateKey(ctx,
			&api.CreateKeyRequest{Key: key})
		t.Logf("createKey, err: %+v, %v", createKey, err)
		require.NoError(t, err)
		require.NotEqual(t, key.GetId(), createKey.GetKey().GetId())
		require.WithinDuration(t, time.Now(), createKey.GetKey().GetCreatedAt().AsTime(),
			2*time.Second)
		require.NotEmpty(t, createKey.GetToken())
	})

	t.Run("Create valid key with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		sessCli := api.NewSessionServiceClient(secondaryViewerGRPCConn)
		createKey, err := sessCli.CreateKey(ctx,
			&api.CreateKeyRequest{Key: random.Key("api-key", uuid.NewString())})
		t.Logf("createKey, err: %+v, %v", createKey, err)
		require.Nil(t, createKey)
		require.EqualError(t, err, "rpc error: code = PermissionDenied desc = "+
			"permission denied, ADMIN role required")
	})

	t.Run("Create sysadmin key as non-sysadmin", func(t *testing.T) {
		t.Parallel()

		key := random.Key("api-key", uuid.NewString())
		key.Role = api.Role_SYS_ADMIN

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		sessCli := api.NewSessionServiceClient(globalAdminGRPCConn)
		createKey, err := sessCli.CreateKey(ctx,
			&api.CreateKeyRequest{Key: key})
		t.Logf("createKey, err: %+v, %v", createKey, err)
		require.Nil(t, createKey)
		require.EqualError(t, err, "rpc error: code = PermissionDenied desc = "+
			"permission denied, role modification not allowed")
	})

	t.Run("Create invalid key", func(t *testing.T) {
		t.Parallel()

		key := random.Key("api-key", uuid.NewString())
		key.Name = "api-key-" + random.String(80)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		sessCli := api.NewSessionServiceClient(globalAdminGRPCConn)
		createKey, err := sessCli.CreateKey(ctx,
			&api.CreateKeyRequest{Key: key})
		t.Logf("createKey, err: %+v, %v", createKey, err)
		require.Nil(t, createKey)
		require.EqualError(t, err, "rpc error: code = InvalidArgument desc = "+
			"invalid CreateKeyRequest.Key: embedded message failed validation "+
			"| caused by: invalid Key.Name: value length must be between 5 "+
			"and 80 runes, inclusive")
	})
}

func TestDeleteKey(t *testing.T) {
	t.Parallel()

	t.Run("Delete key by valid ID", func(t *testing.T) {
		t.Parallel()

		key := random.Key("api-key", uuid.NewString())
		key.Role = api.Role_AUTHENTICATOR

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		sessCli := api.NewSessionServiceClient(globalAdminGRPCConn)
		createKey, err := sessCli.CreateKey(ctx,
			&api.CreateKeyRequest{Key: key})
		t.Logf("createKey, err: %+v, %v", createKey, err)
		require.NoError(t, err)

		_, err = sessCli.DeleteKey(ctx,
			&api.DeleteKeyRequest{Id: createKey.GetKey().GetId()})
		t.Logf("err: %v", err)
		require.NoError(t, err)

		t.Run("Delete key by deleted ID", func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(),
				testTimeout)
			defer cancel()

			sessCli := api.NewSessionServiceClient(globalAdminKeyGRPCConn)
			_, err := sessCli.DeleteKey(ctx,
				&api.DeleteKeyRequest{Id: createKey.GetKey().GetId()})
			t.Logf("err: %v", err)
			require.EqualError(t, err, "rpc error: code = NotFound desc = "+
				"object not found")
		})
	})

	// Test auth interceptor for disabled API key.
	t.Run("Delete key with invalid key", func(t *testing.T) {
		t.Parallel()

		key := random.Key("api-key", uuid.NewString())
		key.Role = api.Role_ADMIN

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		sessCli := api.NewSessionServiceClient(globalAdminGRPCConn)
		createKey, err := sessCli.CreateKey(ctx,
			&api.CreateKeyRequest{Key: key})
		t.Logf("createKey, err: %+v, %v", createKey, err)
		require.NoError(t, err)

		opts := []grpc.DialOption{
			grpc.WithBlock(),
			grpc.FailOnNonTempDialError(true),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithPerRPCCredentials(&credential{token: createKey.GetToken()}),
		}
		keyConn, err := grpc.Dial(iapi.GRPCHost+iapi.GRPCPort, opts...)
		require.NoError(t, err)

		sessCli = api.NewSessionServiceClient(keyConn)
		_, err = sessCli.DeleteKey(ctx,
			&api.DeleteKeyRequest{Id: createKey.GetKey().GetId()})
		t.Logf("err: %v", err)
		require.NoError(t, err)

		_, err = sessCli.DeleteKey(ctx,
			&api.DeleteKeyRequest{Id: createKey.GetKey().GetId()})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = Unauthenticated desc = "+
			"unauthorized")
	})

	t.Run("Delete key with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		sessCli := api.NewSessionServiceClient(secondaryViewerGRPCConn)
		_, err := sessCli.DeleteKey(ctx,
			&api.DeleteKeyRequest{Id: uuid.NewString()})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = PermissionDenied "+
			"desc = permission denied, ADMIN role required")
	})

	t.Run("Delete key by unknown ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		sessCli := api.NewSessionServiceClient(globalAdminGRPCConn)
		_, err := sessCli.DeleteKey(ctx,
			&api.DeleteKeyRequest{Id: uuid.NewString()})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = NotFound desc = object "+
			"not found")
	})

	t.Run("Deletes are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		key := random.Key("api-key", uuid.NewString())
		key.Role = api.Role_AUTHENTICATOR

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		sessCli := api.NewSessionServiceClient(globalAdminGRPCConn)
		createKey, err := sessCli.CreateKey(ctx,
			&api.CreateKeyRequest{Key: key})
		t.Logf("createKey, err: %+v, %v", createKey, err)
		require.NoError(t, err)

		secCli := api.NewSessionServiceClient(secondaryAdminGRPCConn)
		_, err = secCli.DeleteKey(ctx,
			&api.DeleteKeyRequest{Id: createKey.GetKey().GetId()})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = NotFound desc = object "+
			"not found")
	})
}

func TestListKeys(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	keyIDs := []string{}
	keyNames := []string{}
	keyRoles := []api.Role{}
	for i := 0; i < 3; i++ {
		key := random.Key("api-key", uuid.NewString())
		key.Role = api.Role_AUTHENTICATOR

		sessCli := api.NewSessionServiceClient(globalAdminGRPCConn)
		createKey, err := sessCli.CreateKey(ctx,
			&api.CreateKeyRequest{Key: key})
		t.Logf("createKey, err: %+v, %v", createKey, err)
		require.NoError(t, err)

		keyIDs = append(keyIDs, createKey.GetKey().GetId())
		keyNames = append(keyNames, createKey.GetKey().GetName())
		keyRoles = append(keyRoles, createKey.GetKey().GetRole())
	}

	t.Run("List keys by valid org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		sessCli := api.NewSessionServiceClient(globalAdminGRPCConn)
		listKeys, err := sessCli.ListKeys(ctx, &api.ListKeysRequest{})
		t.Logf("listKeys, err: %+v, %v", listKeys, err)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(listKeys.GetKeys()), 3)
		require.GreaterOrEqual(t, listKeys.GetTotalSize(), int32(3))

		var found bool
		for _, key := range listKeys.GetKeys() {
			if key.GetId() == keyIDs[len(keyIDs)-1] &&
				key.GetName() == keyNames[len(keyNames)-1] &&
				key.GetRole() == keyRoles[len(keyRoles)-1] {
				found = true
			}
		}
		require.True(t, found)
	})

	t.Run("List keys by valid org ID with next page", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		sessCli := api.NewSessionServiceClient(globalAdminKeyGRPCConn)
		listKeys, err := sessCli.ListKeys(ctx,
			&api.ListKeysRequest{PageSize: 2})
		t.Logf("listKeys, err: %+v, %v", listKeys, err)
		require.NoError(t, err)
		require.Len(t, listKeys.GetKeys(), 2)
		require.NotEmpty(t, listKeys.GetNextPageToken())
		require.GreaterOrEqual(t, listKeys.GetTotalSize(), int32(3))

		nextKeys, err := sessCli.ListKeys(ctx, &api.ListKeysRequest{
			PageSize: 2, PageToken: listKeys.GetNextPageToken(),
		})
		t.Logf("nextKeys, err: %+v, %v", nextKeys, err)
		require.NoError(t, err)
		require.NotEmpty(t, nextKeys.GetKeys())
		require.GreaterOrEqual(t, nextKeys.GetTotalSize(), int32(3))
	})

	t.Run("List keys with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		secCli := api.NewSessionServiceClient(secondaryViewerGRPCConn)
		listKeys, err := secCli.ListKeys(ctx, &api.ListKeysRequest{})
		t.Logf("listKeys, err: %+v, %v", listKeys, err)
		require.Nil(t, listKeys)
		require.EqualError(t, err, "rpc error: code = PermissionDenied desc = "+
			"permission denied, ADMIN role required")
	})

	t.Run("Lists are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		secCli := api.NewSessionServiceClient(secondaryAdminGRPCConn)
		listKeys, err := secCli.ListKeys(ctx, &api.ListKeysRequest{})
		t.Logf("listKeys, err: %+v, %v", listKeys, err)
		require.NoError(t, err)
		require.Len(t, listKeys.GetKeys(), 1)
		require.Equal(t, int32(1), listKeys.GetTotalSize())
	})

	t.Run("List keys by invalid page token", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		sessCli := api.NewSessionServiceClient(globalAdminGRPCConn)
		listKeys, err := sessCli.ListKeys(ctx,
			&api.ListKeysRequest{PageToken: badUUID})
		t.Logf("listKeys, err: %+v, %v", listKeys, err)
		require.Nil(t, listKeys)
		require.EqualError(t, err, "rpc error: code = InvalidArgument desc = "+
			"invalid page token")
	})
}
