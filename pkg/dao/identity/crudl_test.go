// +build !unit

package identity

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/hermes/pkg/dao"
	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const testTimeout = 10 * time.Second

func TestCreate(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	createOrg, err := globalOrgDAO.Create(ctx, random.Org("dao-identity"))
	t.Logf("createOrg, err: %+v, %v", createOrg, err)
	require.NoError(t, err)

	createApp, err := globalAppDAO.Create(ctx, random.App("dao-identity",
		createOrg.Id))
	t.Logf("createApp, err: %+v, %v", createApp, err)
	require.NoError(t, err)

	t.Run("Create valid HOTP identity", func(t *testing.T) {
		t.Parallel()

		identity := random.HOTPIdentity("dao-identity", createOrg.Id,
			createApp.Id)
		createIdentity, _ := proto.Clone(identity).(*api.Identity)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, createOTP, retSecret, err := globalIdentityDAO.Create(
			ctx, createIdentity)
		t.Logf("identity, createIdentity, createOTP, retSecret, err: %+v, "+
			"%+v, %#v, %v, %v", identity, createIdentity, createOTP, retSecret,
			err)
		require.NoError(t, err)
		require.NotEqual(t, identity.Id, createIdentity.Id)
		require.Equal(t, api.IdentityStatus_UNVERIFIED, createIdentity.Status)
		require.WithinDuration(t, time.Now(), createIdentity.CreatedAt.AsTime(),
			2*time.Second)
		require.WithinDuration(t, time.Now(), createIdentity.UpdatedAt.AsTime(),
			2*time.Second)
		require.NotNil(t, createOTP)
		require.True(t, retSecret)
	})

	t.Run("Create valid SMS identity", func(t *testing.T) {
		t.Parallel()

		identity := random.SMSIdentity("dao-identity", createOrg.Id,
			createApp.Id)
		createIdentity, _ := proto.Clone(identity).(*api.Identity)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, createOTP, retSecret, err := globalIdentityDAO.Create(
			ctx, createIdentity)
		t.Logf("identity, createIdentity, createOTP, retSecret, err: %+v, "+
			"%+v, %#v, %v, %v", identity, createIdentity, createOTP, retSecret,
			err)
		require.NoError(t, err)
		require.NotEqual(t, identity.Id, createIdentity.Id)
		require.Equal(t, api.IdentityStatus_UNVERIFIED, createIdentity.Status)
		require.WithinDuration(t, time.Now(), createIdentity.CreatedAt.AsTime(),
			2*time.Second)
		require.WithinDuration(t, time.Now(), createIdentity.UpdatedAt.AsTime(),
			2*time.Second)
		require.NotNil(t, createOTP)
		require.False(t, retSecret)
	})

	t.Run("Create invalid identity", func(t *testing.T) {
		t.Parallel()

		identity := random.HOTPIdentity("dao-identity", createOrg.Id,
			createApp.Id)
		identity.Comment = "dao-identity-" + random.String(80)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, createOTP, retSecret, err := globalIdentityDAO.Create(
			ctx, identity)
		t.Logf("identity, createIdentity, createOTP, retSecret, err: %+v, "+
			"%+v, %#v, %v, %v", identity, createIdentity, createOTP, retSecret,
			err)
		require.Nil(t, createIdentity)
		require.Nil(t, createOTP)
		require.False(t, retSecret)
		require.ErrorIs(t, err, dao.ErrInvalidFormat)
	})

	t.Run("Create valid identity by unknown app", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, createOTP, retSecret, err := globalIdentityDAO.Create(
			ctx, random.HOTPIdentity("dao-identity", createOrg.Id,
				uuid.NewString()))
		t.Logf("createIdentity, createOTP, retSecret, err: %+v, %#v, %v, %v",
			createIdentity, createOTP, retSecret, err)
		require.Nil(t, createIdentity)
		require.Nil(t, createOTP)
		require.False(t, retSecret)
		require.ErrorIs(t, err, dao.ErrInvalidFormat)
	})
}

func TestRead(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	createOrg, err := globalOrgDAO.Create(ctx, random.Org("dao-identity"))
	t.Logf("createOrg, err: %+v, %v", createOrg, err)
	require.NoError(t, err)

	createApp, err := globalAppDAO.Create(ctx, random.App("dao-identity",
		createOrg.Id))
	t.Logf("createApp, err: %+v, %v", createApp, err)
	require.NoError(t, err)

	createIdentity, createOTP, _, err := globalIdentityDAO.Create(ctx,
		random.HOTPIdentity("dao-identity", createOrg.Id, createApp.Id))
	t.Logf("createIdentity, createOTP, err: %+v, %#v, %v", createIdentity,
		createOTP, err)
	require.NoError(t, err)

	t.Run("Read HOTP identity by valid ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		readIdentity, readOTP, err := globalIdentityDAO.Read(ctx,
			createIdentity.Id, createIdentity.OrgId, createIdentity.AppId)
		t.Logf("readIdentity, readOTP, err: %+v, %#v, %v", readIdentity,
			readOTP, err)
		require.NoError(t, err)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(createIdentity, readIdentity) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", createIdentity, readIdentity)
		}

		require.Equal(t, createOTP, readOTP)
		require.Equal(t, createIdentity.GetSoftwareHotpMethod().Hash,
			hashCryptoToAPI[readOTP.Hash])
		require.Equal(t, createIdentity.GetSoftwareHotpMethod().Digits,
			int32(readOTP.Digits))
	})

	t.Run("Read SMS identity by valid ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, createOTP, _, err := globalIdentityDAO.Create(ctx,
			random.SMSIdentity("dao-identity", createOrg.Id, createApp.Id))
		t.Logf("createIdentity, createOTP, err: %+v, %#v, %v", createIdentity,
			createOTP, err)
		require.NoError(t, err)

		readIdentity, readOTP, err := globalIdentityDAO.Read(ctx,
			createIdentity.Id, createIdentity.OrgId, createIdentity.AppId)
		t.Logf("readIdentity, readOTP, err: %+v, %#v, %v", readIdentity,
			readOTP, err)
		require.NoError(t, err)
		require.NotNil(t, readOTP)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(createIdentity, readIdentity) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", createIdentity, readIdentity)
		}

		require.Equal(t, createOTP, readOTP)
	})

	t.Run("Read identity by unknown ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		readIdentity, readOTP, err := globalIdentityDAO.Read(ctx,
			uuid.NewString(), createIdentity.OrgId, createIdentity.AppId)
		t.Logf("readIdentity, readOTP, err: %+v, %#v, %v", readIdentity,
			readOTP, err)
		require.Nil(t, readIdentity)
		require.Nil(t, readOTP)
		require.Equal(t, dao.ErrNotFound, err)
	})

	t.Run("Read identity by unknown app", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		readIdentity, readOTP, err := globalIdentityDAO.Read(ctx,
			createIdentity.Id, createIdentity.OrgId, uuid.NewString())
		t.Logf("readIdentity, readOTP, err: %+v, %#v, %v", readIdentity,
			readOTP, err)
		require.Nil(t, readIdentity)
		require.Nil(t, readOTP)
		require.Equal(t, dao.ErrNotFound, err)
	})

	t.Run("Reads are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		readIdentity, readOTP, err := globalIdentityDAO.Read(ctx,
			createIdentity.Id, uuid.NewString(), createIdentity.AppId)
		t.Logf("readIdentity, readOTP, err: %+v, %#v, %v", readIdentity,
			readOTP, err)
		require.Nil(t, readIdentity)
		require.Nil(t, readOTP)
		require.Equal(t, dao.ErrNotFound, err)
	})

	t.Run("Read identity by invalid ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		readIdentity, readOTP, err := globalIdentityDAO.Read(ctx,
			random.String(10), createIdentity.OrgId, createIdentity.AppId)
		t.Logf("readIdentity, readOTP, err: %+v, %#v, %v", readIdentity,
			readOTP, err)
		require.Nil(t, readIdentity)
		require.Nil(t, readOTP)
		require.ErrorIs(t, err, dao.ErrInvalidFormat)
	})
}

func TestUpdateStatus(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	createOrg, err := globalOrgDAO.Create(ctx, random.Org("dao-identity"))
	t.Logf("createOrg, err: %+v, %v", createOrg, err)
	require.NoError(t, err)

	createApp, err := globalAppDAO.Create(ctx, random.App("dao-identity",
		createOrg.Id))
	t.Logf("createApp, err: %+v, %v", createApp, err)
	require.NoError(t, err)

	t.Run("Update identity status by valid ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, _, _, err := globalIdentityDAO.Create(ctx,
			random.HOTPIdentity("dao-identity", createOrg.Id, createApp.Id))
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		updateIdentity, err := globalIdentityDAO.UpdateStatus(ctx,
			createIdentity.Id, createOrg.Id, createApp.Id,
			api.IdentityStatus_ACTIVATED)
		t.Logf("updateIdentity, err: %+v, %v", updateIdentity, err)
		require.NoError(t, err)
		require.Equal(t, api.IdentityStatus_ACTIVATED, updateIdentity.Status)
		require.WithinDuration(t, time.Now(), createIdentity.UpdatedAt.AsTime(),
			2*time.Second)
	})

	t.Run("Update identity status by unknown ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		updateIdentity, err := globalIdentityDAO.UpdateStatus(ctx,
			uuid.NewString(), createOrg.Id, createApp.Id,
			api.IdentityStatus_ACTIVATED)
		t.Logf("updateIdentity, err: %+v, %v", updateIdentity, err)
		require.Nil(t, updateIdentity)
		require.Equal(t, dao.ErrNotFound, err)
	})

	t.Run("Status updates are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, _, _, err := globalIdentityDAO.Create(ctx,
			random.HOTPIdentity("dao-identity", createOrg.Id, createApp.Id))
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		updateIdentity, err := globalIdentityDAO.UpdateStatus(ctx,
			createIdentity.Id, uuid.NewString(), createApp.Id,
			api.IdentityStatus_ACTIVATED)
		t.Logf("updateIdentity, err: %+v, %v", updateIdentity, err)
		require.Nil(t, updateIdentity)
		require.Equal(t, dao.ErrNotFound, err)
	})
}

func TestDelete(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	createOrg, err := globalOrgDAO.Create(ctx, random.Org("dao-identity"))
	t.Logf("createOrg, err: %+v, %v", createOrg, err)
	require.NoError(t, err)

	createApp, err := globalAppDAO.Create(ctx, random.App("dao-identity",
		createOrg.Id))
	t.Logf("createApp, err: %+v, %v", createApp, err)
	require.NoError(t, err)

	t.Run("Delete identity by valid ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, _, _, err := globalIdentityDAO.Create(ctx,
			random.HOTPIdentity("dao-identity", createOrg.Id, createApp.Id))
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		err = globalIdentityDAO.Delete(ctx, createIdentity.Id, createOrg.Id,
			createIdentity.AppId)
		t.Logf("err: %v", err)
		require.NoError(t, err)

		t.Run("Read identity by deleted ID", func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(),
				testTimeout)
			defer cancel()

			readIdentity, readOTP, err := globalIdentityDAO.Read(ctx,
				createIdentity.Id, createOrg.Id, createIdentity.AppId)
			t.Logf("readIdentity, readOTP, err: %+v, %#v, %v", readIdentity,
				readOTP, err)
			require.Nil(t, readIdentity)
			require.Nil(t, readOTP)
			require.Equal(t, dao.ErrNotFound, err)
		})
	})

	t.Run("Delete identity by unknown ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		err := globalIdentityDAO.Delete(ctx, uuid.NewString(), createOrg.Id,
			createApp.Id)
		t.Logf("err: %v", err)
		require.Equal(t, dao.ErrNotFound, err)
	})

	t.Run("Delete identity by unknown app", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, _, _, err := globalIdentityDAO.Create(ctx,
			random.HOTPIdentity("dao-identity", createOrg.Id, createApp.Id))
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		err = globalIdentityDAO.Delete(ctx, createIdentity.Id, createOrg.Id,
			uuid.NewString())
		t.Logf("err: %v", err)
		require.Equal(t, dao.ErrNotFound, err)
	})

	t.Run("Deletes are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, _, _, err := globalIdentityDAO.Create(ctx,
			random.HOTPIdentity("dao-identity", createOrg.Id, createApp.Id))
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		err = globalIdentityDAO.Delete(ctx, createIdentity.Id, uuid.NewString(),
			createApp.Id)
		t.Logf("err: %v", err)
		require.Equal(t, dao.ErrNotFound, err)
	})
}

func TestList(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	createOrg, err := globalOrgDAO.Create(ctx, random.Org("dao-identity"))
	t.Logf("createOrg, err: %+v, %v", createOrg, err)
	require.NoError(t, err)

	createApp, err := globalAppDAO.Create(ctx, random.App("dao-identity",
		createOrg.Id))
	t.Logf("createApp, err: %+v, %v", createApp, err)
	require.NoError(t, err)

	identityIDs := []string{}
	identityComments := []string{}
	identityTSes := []time.Time{}
	for i := 0; i < 3; i++ {
		createIdentity, _, _, err := globalIdentityDAO.Create(ctx,
			random.HOTPIdentity("dao-identity", createOrg.Id, createApp.Id))
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		identityIDs = append(identityIDs, createIdentity.Id)
		identityComments = append(identityComments, createIdentity.Comment)
		identityTSes = append(identityTSes, createIdentity.CreatedAt.AsTime())
	}

	t.Run("List identities by valid org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		listIdentities, listCount, err := globalIdentityDAO.List(ctx,
			createOrg.Id, time.Time{}, "", 0, "")
		t.Logf("listIdentities, listCount, err: %+v, %v, %v", listIdentities,
			listCount, err)
		require.NoError(t, err)
		require.Len(t, listIdentities, 3)
		require.Equal(t, int32(3), listCount)

		var found bool
		for _, identity := range listIdentities {
			if identity.Id == identityIDs[len(identityIDs)-1] &&
				identity.Comment == identityComments[len(identityComments)-1] {
				found = true
			}
		}
		require.True(t, found)
	})

	t.Run("List identities by valid org ID and pagination", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		listIdentities, listCount, err := globalIdentityDAO.List(ctx,
			createOrg.Id, identityTSes[0], identityIDs[0], 5, "")
		t.Logf("listIdentities, listCount, err: %+v, %v, %v", listIdentities,
			listCount, err)
		require.NoError(t, err)
		require.Len(t, listIdentities, 2)
		require.Equal(t, int32(3), listCount)

		var found bool
		for _, identity := range listIdentities {
			if identity.Id == identityIDs[len(identityIDs)-1] &&
				identity.Comment == identityComments[len(identityComments)-1] {
				found = true
			}
		}
		require.True(t, found)
	})

	t.Run("List identities by valid org ID with limit", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		listIdentities, listCount, err := globalIdentityDAO.List(ctx,
			createOrg.Id, time.Time{}, "", 1, "")
		t.Logf("listIdentities, listCount, err: %+v, %v, %v", listIdentities,
			listCount, err)
		require.NoError(t, err)
		require.Len(t, listIdentities, 1)
		require.Equal(t, int32(3), listCount)
	})

	t.Run("List identities with app filter", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		listIdentities, listCount, err := globalIdentityDAO.List(ctx,
			createOrg.Id, time.Time{}, "", 0, createApp.Id)
		t.Logf("listIdentities, listCount, err: %+v, %v, %v", listIdentities,
			listCount, err)
		require.NoError(t, err)
		require.Len(t, listIdentities, 3)
		require.Equal(t, int32(3), listCount)

		var found bool
		for _, identity := range listIdentities {
			if identity.Id == identityIDs[len(identityIDs)-1] &&
				identity.Comment == identityComments[len(identityComments)-1] {
				found = true
			}
		}
		require.True(t, found)
	})

	t.Run("List identities with app filter and pagination", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		listIdentities, listCount, err := globalIdentityDAO.List(ctx,
			createOrg.Id, identityTSes[0], identityIDs[0], 5, createApp.Id)
		t.Logf("listIdentities, listCount, err: %+v, %v, %v", listIdentities,
			listCount, err)
		require.NoError(t, err)
		require.Len(t, listIdentities, 2)
		require.Equal(t, int32(3), listCount)

		var found bool
		for _, identity := range listIdentities {
			if identity.Id == identityIDs[len(identityIDs)-1] &&
				identity.Comment == identityComments[len(identityComments)-1] {
				found = true
			}
		}
		require.True(t, found)
	})

	t.Run("List identities by unknown app", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		listIdentities, listCount, err := globalIdentityDAO.List(ctx,
			uuid.NewString(), time.Time{}, "", 0, uuid.NewString())
		t.Logf("listIdentities, listCount, err: %+v, %v, %v", listIdentities,
			listCount, err)
		require.NoError(t, err)
		require.Len(t, listIdentities, 0)
		require.Equal(t, int32(0), listCount)
	})

	t.Run("Lists are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		listIdentities, listCount, err := globalIdentityDAO.List(ctx,
			uuid.NewString(), time.Time{}, "", 0, "")
		t.Logf("listIdentities, listCount, err: %+v, %v, %v", listIdentities,
			listCount, err)
		require.NoError(t, err)
		require.Len(t, listIdentities, 0)
		require.Equal(t, int32(0), listCount)
	})

	t.Run("List identities by invalid org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		listIdentities, listCount, err := globalIdentityDAO.List(ctx,
			random.String(10), time.Time{}, "", 0, "")
		t.Logf("listIdentities, listCount, err: %+v, %v, %v", listIdentities,
			listCount, err)
		require.Nil(t, listIdentities)
		require.Equal(t, int32(0), listCount)
		require.ErrorIs(t, err, dao.ErrInvalidFormat)
	})
}
