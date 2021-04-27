package random

import (
	"github.com/google/uuid"
	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/api/go/common"
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
		Role: []common.Role{
			common.Role_VIEWER,
			common.Role_AUTHENTICATOR,
			common.Role_ADMIN,
			common.Role_SYS_ADMIN,
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
		Role: []common.Role{
			common.Role_VIEWER,
			common.Role_AUTHENTICATOR,
			common.Role_ADMIN,
			common.Role_SYS_ADMIN,
		}[Intn(4)],
	}
}

// App generates a random application with prefixed identifiers.
func App(prefix, orgID string) *api.App {
	return &api.App{
		Id:               uuid.NewString(),
		OrgId:            orgID,
		Name:             prefix + "-" + String(10),
		SubjectTemplate:  `{{displayName}} verification code`,
		TextBodyTemplate: `Your {{displayName}} verification code is: 1234567`,
		HtmlBodyTemplate: []byte(`<html><body>Your {{displayName}} ` +
			`verification code is: 1234567</body></html>`),
	}
}

// Identity generates a random identity with prefixed identifiers.
func Identity(prefix, orgID, appID string) *api.Identity {
	return &api.Identity{
		Id:      uuid.NewString(),
		OrgId:   orgID,
		AppId:   appID,
		Comment: prefix + "-" + String(10),
		Status: []api.IdentityStatus{
			api.IdentityStatus_UNVERIFIED,
			api.IdentityStatus_ACTIVATED,
		}[Intn(2)],
		MethodOneof: &api.Identity_SoftwareHotpMethod{
			SoftwareHotpMethod: &api.SoftwareHOTPMethod{Digits: 6},
		},
	}
}
