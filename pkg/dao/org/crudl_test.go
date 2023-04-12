//go:build !unit

package org

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/hermes/pkg/dao"
	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const testTimeout = 8 * time.Second

func TestCreate(t *testing.T) {
	t.Parallel()

	t.Run("Create valid org", func(t *testing.T) {
		t.Parallel()

		org := random.Org("dao-org")
		createOrg, _ := proto.Clone(org).(*api.Org)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createOrg, err := globalOrgDAO.Create(ctx, createOrg)
		t.Logf("org, createOrg, err: %+v, %+v, %v", org, createOrg, err)
		require.NoError(t, err)
		require.NotEqual(t, org.Id, createOrg.Id)
		require.Equal(t, org.Name, createOrg.Name)
		require.WithinDuration(t, time.Now(), createOrg.CreatedAt.AsTime(),
			2*time.Second)
		require.WithinDuration(t, time.Now(), createOrg.UpdatedAt.AsTime(),
			2*time.Second)
	})

	t.Run("Create valid org with uppercase name", func(t *testing.T) {
		t.Parallel()

		org := random.Org("dao-org")
		org.Name = strings.ToUpper(org.Name)
		createOrg, _ := proto.Clone(org).(*api.Org)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createOrg, err := globalOrgDAO.Create(ctx, createOrg)
		t.Logf("org, createOrg, err: %+v, %+v, %v", org, createOrg, err)
		require.NoError(t, err)
		require.NotEqual(t, org.Id, createOrg.Id)
		require.Equal(t, strings.ToLower(org.Name), createOrg.Name)
		require.WithinDuration(t, time.Now(), createOrg.CreatedAt.AsTime(),
			2*time.Second)
		require.WithinDuration(t, time.Now(), createOrg.UpdatedAt.AsTime(),
			2*time.Second)
	})

	t.Run("Create invalid org", func(t *testing.T) {
		t.Parallel()

		org := random.Org("dao-org")
		org.Name = "dao-org-" + random.String(40)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createOrg, err := globalOrgDAO.Create(ctx, org)
		t.Logf("org, createOrg, err: %+v, %+v, %v", org, createOrg, err)
		require.Nil(t, createOrg)
		require.ErrorIs(t, err, dao.ErrInvalidFormat)
	})
}

func TestRead(t *testing.T) {
	t.Parallel()

	t.Run("Read org by valid ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createOrg, err := globalOrgDAO.Create(ctx, random.Org("dao-org"))
		t.Logf("createOrg, err: %+v, %v", createOrg, err)
		require.NoError(t, err)

		readOrg, err := globalOrgDAO.Read(ctx, createOrg.Id)
		t.Logf("readOrg, err: %+v, %v", readOrg, err)
		require.NoError(t, err)
		require.Equal(t, createOrg, readOrg)
	})

	t.Run("Read org by unknown ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		readOrg, err := globalOrgDAO.Read(ctx, uuid.NewString())
		t.Logf("readOrg, err: %+v, %v", readOrg, err)
		require.Nil(t, readOrg)
		require.Equal(t, dao.ErrNotFound, err)
	})

	t.Run("Read org by invalid ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		readOrg, err := globalOrgDAO.Read(ctx, random.String(10))
		t.Logf("readOrg, err: %+v, %v", readOrg, err)
		require.Nil(t, readOrg)
		require.ErrorIs(t, err, dao.ErrInvalidFormat)
	})
}

func TestReadUpdateDeleteCache(t *testing.T) {
	t.Parallel()

	t.Run("Read cached org by valid ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createOrg, err := globalOrgDAOCache.Create(ctx, random.Org("dao-org"))
		t.Logf("createOrg, err: %+v, %v", createOrg, err)
		require.NoError(t, err)

		readOrg, err := globalOrgDAOCache.Read(ctx, createOrg.Id)
		t.Logf("readOrg, err: %+v, %v", readOrg, err)
		require.NoError(t, err)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(createOrg, readOrg) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", createOrg, readOrg)
		}

		readOrg, err = globalOrgDAOCache.Read(ctx, createOrg.Id)
		t.Logf("readOrg, err: %+v, %v", readOrg, err)
		require.NoError(t, err)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(createOrg, readOrg) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", createOrg, readOrg)
		}
	})

	t.Run("Read updated org by valid ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createOrg, err := globalOrgDAOCache.Create(ctx, random.Org("dao-org"))
		t.Logf("createOrg, err: %+v, %v", createOrg, err)
		require.NoError(t, err)

		// Update org fields.
		createOrg.Name = "dao-org-" + random.String(10)
		createOrg.Status = api.Status_DISABLED
		createOrg.Plan = api.Plan_PRO
		updateOrg, _ := proto.Clone(createOrg).(*api.Org)

		updateOrg, err = globalOrgDAOCache.Update(ctx, updateOrg)
		t.Logf("createOrg, updateOrg, err: %+v, %+v, %v", createOrg, updateOrg,
			err)
		require.NoError(t, err)
		require.Equal(t, createOrg.Name, updateOrg.Name)
		require.Equal(t, createOrg.Status, updateOrg.Status)
		require.Equal(t, createOrg.Plan, updateOrg.Plan)
		require.True(t, updateOrg.UpdatedAt.AsTime().After(
			updateOrg.CreatedAt.AsTime()))
		require.WithinDuration(t, createOrg.CreatedAt.AsTime(),
			updateOrg.UpdatedAt.AsTime(), 2*time.Second)

		readOrg, err := globalOrgDAOCache.Read(ctx, createOrg.Id)
		t.Logf("readOrg, err: %+v, %v", readOrg, err)
		require.NoError(t, err)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(updateOrg, readOrg) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", updateOrg, readOrg)
		}
	})

	t.Run("Read deleted org by valid ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createOrg, err := globalOrgDAOCache.Create(ctx, random.Org("dao-org"))
		t.Logf("createOrg, err: %+v, %v", createOrg, err)
		require.NoError(t, err)

		readOrg, err := globalOrgDAOCache.Read(ctx, createOrg.Id)
		t.Logf("readOrg, err: %+v, %v", readOrg, err)
		require.NoError(t, err)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(createOrg, readOrg) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", createOrg, readOrg)
		}

		err = globalOrgDAOCache.Delete(ctx, createOrg.Id)
		t.Logf("err: %v", err)
		require.NoError(t, err)

		readOrg, err = globalOrgDAOCache.Read(ctx, createOrg.Id)
		t.Logf("readOrg, err: %+v, %v", readOrg, err)
		require.Nil(t, readOrg)
		require.Equal(t, dao.ErrNotFound, err)
	})

	t.Run("Read org by unknown ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		readOrg, err := globalOrgDAOCache.Read(ctx, uuid.NewString())
		t.Logf("readOrg, err: %+v, %v", readOrg, err)
		require.Nil(t, readOrg)
		require.Equal(t, dao.ErrNotFound, err)
	})

	t.Run("Read org by invalid ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		readOrg, err := globalOrgDAOCache.Read(ctx, random.String(10))
		t.Logf("readOrg, err: %+v, %v", readOrg, err)
		require.Nil(t, readOrg)
		require.ErrorIs(t, err, dao.ErrInvalidFormat)
	})
}

func TestUpdate(t *testing.T) {
	t.Parallel()

	t.Run("Update org by valid org", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createOrg, err := globalOrgDAO.Create(ctx, random.Org("dao-org"))
		t.Logf("createOrg, err: %+v, %v", createOrg, err)
		require.NoError(t, err)

		// Update org fields.
		createOrg.Name = "dao-org-" + random.String(10)
		createOrg.Status = api.Status_DISABLED
		createOrg.Plan = api.Plan_PRO
		updateOrg, _ := proto.Clone(createOrg).(*api.Org)

		updateOrg, err = globalOrgDAO.Update(ctx, updateOrg)
		t.Logf("createOrg, updateOrg, err: %+v, %+v, %v", createOrg, updateOrg,
			err)
		require.NoError(t, err)
		require.Equal(t, createOrg.Name, updateOrg.Name)
		require.Equal(t, createOrg.Status, updateOrg.Status)
		require.Equal(t, createOrg.Plan, updateOrg.Plan)
		require.True(t, updateOrg.UpdatedAt.AsTime().After(
			updateOrg.CreatedAt.AsTime()))
		require.WithinDuration(t, createOrg.CreatedAt.AsTime(),
			updateOrg.UpdatedAt.AsTime(), 2*time.Second)

		readOrg, err := globalOrgDAO.Read(ctx, createOrg.Id)
		t.Logf("readOrg, err: %+v, %v", readOrg, err)
		require.NoError(t, err)
		require.Equal(t, updateOrg, readOrg)
	})

	t.Run("Update unknown org", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		updateOrg, err := globalOrgDAO.Update(ctx, random.Org("dao-org"))
		t.Logf("updateOrg, err: %+v, %v", updateOrg, err)
		require.Nil(t, updateOrg)
		require.Equal(t, dao.ErrNotFound, err)
	})

	t.Run("Update org by invalid org", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createOrg, err := globalOrgDAO.Create(ctx, random.Org("dao-org"))
		t.Logf("createOrg, err: %+v, %v", createOrg, err)
		require.NoError(t, err)

		// Update org fields.
		createOrg.Name = "dao-org-" + random.String(40)
		updateOrg, _ := proto.Clone(createOrg).(*api.Org)

		updateOrg, err = globalOrgDAO.Update(ctx, updateOrg)
		t.Logf("createOrg, updateOrg, err: %+v, %+v, %v", createOrg, updateOrg,
			err)
		require.Nil(t, updateOrg)
		require.ErrorIs(t, err, dao.ErrInvalidFormat)
	})
}

func TestDelete(t *testing.T) {
	t.Parallel()

	t.Run("Delete org by valid ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createOrg, err := globalOrgDAO.Create(ctx, random.Org("dao-org"))
		t.Logf("createOrg, err: %+v, %v", createOrg, err)
		require.NoError(t, err)

		err = globalOrgDAO.Delete(ctx, createOrg.Id)
		t.Logf("err: %v", err)
		require.NoError(t, err)

		t.Run("Read org by deleted ID", func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(),
				testTimeout)
			defer cancel()

			readOrg, err := globalOrgDAO.Read(ctx, createOrg.Id)
			t.Logf("readOrg, err: %+v, %v", readOrg, err)
			require.Nil(t, readOrg)
			require.Equal(t, dao.ErrNotFound, err)
		})
	})

	t.Run("Delete org by unknown ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		err := globalOrgDAO.Delete(ctx, uuid.NewString())
		t.Logf("err: %v", err)
		require.Equal(t, dao.ErrNotFound, err)
	})
}

func TestList(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	orgIDs := []string{}
	orgNames := []string{}
	orgPlans := []api.Plan{}
	orgTSes := []time.Time{}
	for i := 0; i < 3; i++ {
		createOrg, err := globalOrgDAO.Create(ctx, random.Org("dao-org"))
		t.Logf("createOrg, err: %+v, %v", createOrg, err)
		require.NoError(t, err)

		orgIDs = append(orgIDs, createOrg.Id)
		orgNames = append(orgNames, createOrg.Name)
		orgPlans = append(orgPlans, createOrg.Plan)
		orgTSes = append(orgTSes, createOrg.CreatedAt.AsTime())
	}

	t.Run("List orgs", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		listOrgs, listCount, err := globalOrgDAO.List(ctx, time.Time{}, "", 0)
		t.Logf("listOrgs, listCount, err: %+v, %v, %v", listOrgs, listCount,
			err)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(listOrgs), 3)
		require.GreaterOrEqual(t, listCount, int32(3))

		var found bool
		for _, org := range listOrgs {
			if org.Id == orgIDs[len(orgIDs)-1] &&
				org.Name == orgNames[len(orgNames)-1] &&
				org.Plan == orgPlans[len(orgPlans)-1] {
				found = true
			}
		}
		require.True(t, found)
	})

	t.Run("List orgs with pagination", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		listOrgs, listCount, err := globalOrgDAO.List(ctx, orgTSes[1],
			orgIDs[1], 1)
		t.Logf("listOrgs, listCount, err: %+v, %v, %v", listOrgs, listCount,
			err)
		require.NoError(t, err)
		require.Len(t, listOrgs, 1)
		require.GreaterOrEqual(t, listCount, int32(3))
	})

	t.Run("List orgs with limit", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		listOrgs, listCount, err := globalOrgDAO.List(ctx, time.Time{}, "", 2)
		t.Logf("listOrgs, listCount, err: %+v, %v, %v", listOrgs, listCount,
			err)
		require.NoError(t, err)
		require.Len(t, listOrgs, 2)
		require.GreaterOrEqual(t, listCount, int32(3))
	})
}
