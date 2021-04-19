package random

import (
	"github.com/google/uuid"
	"github.com/ownmfa/api/go/api"
)

// Org generates a random org with prefixed identifiers.
func Org(prefix string) *api.Org {
	return &api.Org{
		Id:          uuid.NewString(),
		Name:        prefix + "-" + String(10),
		DisplayName: prefix + "-" + String(10),
		Email:       prefix + "-" + Email(),
	}
}

// User generates a random user with prefixed identifiers.
func User(prefix, orgID string) *api.User {
	return &api.User{
		Id:    uuid.NewString(),
		OrgId: orgID,
		Name:  prefix + "-" + String(10),
		Email: prefix + "-" + Email(),
		Role: []api.Role{
			api.Role_VIEWER,
			api.Role_AUTHENTICATOR,
			api.Role_ADMIN,
			api.Role_SYS_ADMIN,
		}[Intn(4)],
		Status: []api.Status{
			api.Status_ACTIVE,
			api.Status_DISABLED,
		}[Intn(2)],
	}
}

// Key generates a random API key with prefixed identifiers.
func Key(prefix, orgID string) *api.Key {
	return &api.Key{
		Id:    uuid.NewString(),
		OrgId: orgID,
		Name:  prefix + "-" + String(10),
		Role: []api.Role{
			api.Role_VIEWER,
			api.Role_AUTHENTICATOR,
			api.Role_ADMIN,
			api.Role_SYS_ADMIN,
		}[Intn(4)],
	}
}
