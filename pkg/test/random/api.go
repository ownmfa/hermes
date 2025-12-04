package random

import (
	"strconv"

	"github.com/google/uuid"
	"github.com/ownmfa/proto/go/api"
)

// Org generates a random org with prefixed identifiers.
func Org(prefix string) *api.Org {
	return &api.Org{
		Id:   uuid.NewString(),
		Name: prefix + "-" + String(10),
		Status: []api.Status{
			api.Status_ACTIVE,
			api.Status_DISABLED,
		}[Intn(2)],
		Plan: []api.Plan{
			api.Plan_PAYMENT_FAIL,
			api.Plan_STARTER,
			api.Plan_PRO,
			api.Plan_ENTERPRISE,
		}[Intn(4)],
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

// App generates a random application with prefixed identifiers.
func App(prefix, orgID string) *api.App {
	return &api.App{
		Id:              uuid.NewString(),
		OrgId:           orgID,
		Name:            prefix + "-" + String(10),
		DisplayName:     prefix + "-" + String(10),
		Email:           prefix + "-" + Email(),
		PushoverKey:     []string{"", String(30)}[Intn(2)],
		SubjectTemplate: `{{.displayName}} verification code`,
		TextBodyTemplate: `Your {{.displayName}} verification code is: ` +
			`1234567.`,
		HtmlBodyTemplate: []byte(`<html><body>Your {{.displayName}} ` +
			`verification code is: 1234567.</body></html>`),
	}
}

// HOTPIdentity generates a random HOTP identity with prefixed identifiers.
func HOTPIdentity(prefix, orgID, appID string) *api.Identity {
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

// SMSIdentity generates a random SMS identity with prefixed identifiers.
func SMSIdentity(prefix, orgID, appID string) *api.Identity {
	return &api.Identity{
		Id:      uuid.NewString(),
		OrgId:   orgID,
		AppId:   appID,
		Comment: prefix + "-" + String(10),
		Status: []api.IdentityStatus{
			api.IdentityStatus_UNVERIFIED,
			api.IdentityStatus_ACTIVATED,
		}[Intn(2)],
		MethodOneof: &api.Identity_SmsMethod{
			// https://en.wikipedia.org/wiki/555_(telephone_number)
			SmsMethod: &api.SMSMethod{Phone: "+1" +
				strconv.Itoa(Intn(900)+100) + "5550" +
				strconv.Itoa(Intn(100)+100)},
		},
	}
}

// PushoverIdentity generates a random Pushover identity with prefixed
// identifiers.
func PushoverIdentity(prefix, orgID, appID string) *api.Identity {
	return &api.Identity{
		Id:      uuid.NewString(),
		OrgId:   orgID,
		AppId:   appID,
		Comment: prefix + "-" + String(10),
		Status: []api.IdentityStatus{
			api.IdentityStatus_UNVERIFIED,
			api.IdentityStatus_ACTIVATED,
		}[Intn(2)],
		MethodOneof: &api.Identity_PushoverMethod{
			PushoverMethod: &api.PushoverMethod{PushoverKey: String(30)},
		},
	}
}

// EmailIdentity generates a random email identity with prefixed identifiers.
func EmailIdentity(prefix, orgID, appID string) *api.Identity {
	return &api.Identity{
		Id:      uuid.NewString(),
		OrgId:   orgID,
		AppId:   appID,
		Comment: prefix + "-" + String(10),
		Status: []api.IdentityStatus{
			api.IdentityStatus_UNVERIFIED,
			api.IdentityStatus_ACTIVATED,
		}[Intn(2)],
		MethodOneof: &api.Identity_EmailMethod{
			EmailMethod: &api.EmailMethod{Email: prefix + "-" + Email()},
		},
	}
}

// BackupCodesIdentity generates a random backup codes identity with prefixed
// identifiers.
func BackupCodesIdentity(prefix, orgID, appID string) *api.Identity {
	return &api.Identity{
		Id:      uuid.NewString(),
		OrgId:   orgID,
		AppId:   appID,
		Comment: prefix + "-" + String(10),
		Status: []api.IdentityStatus{
			api.IdentityStatus_UNVERIFIED,
			api.IdentityStatus_ACTIVATED,
		}[Intn(2)],
		MethodOneof: &api.Identity_BackupCodesMethod{
			BackupCodesMethod: &api.BackupsCodesMethod{
				Passcodes: int32(Intn(5) + 6),
			},
		},
	}
}

// SecurityQuestionsIdentity generates a random security questions identity with
// prefixed identifiers.
func SecurityQuestionsIdentity(prefix, orgID, appID string) *api.Identity {
	return &api.Identity{
		Id:      uuid.NewString(),
		OrgId:   orgID,
		AppId:   appID,
		Comment: prefix + "-" + String(10),
		Status: []api.IdentityStatus{
			api.IdentityStatus_UNVERIFIED,
			api.IdentityStatus_ACTIVATED,
		}[Intn(2)],
		MethodOneof: &api.Identity_SecurityQuestionsMethod{
			SecurityQuestionsMethod: &api.SecurityQuestionsMethod{
				Answer: String(80),
			},
		},
	}
}

// Event generates a random event with prefixed identifiers.
func Event(prefix, orgID string) *api.Event {
	return &api.Event{
		OrgId:      orgID,
		AppId:      uuid.NewString(),
		IdentityId: uuid.NewString(),
		Status: []api.EventStatus{
			api.EventStatus_IDENTITY_CREATED,
			api.EventStatus_CHALLENGE_SENT,
			api.EventStatus_CHALLENGE_NOOP,
			api.EventStatus_CHALLENGE_FAIL,
			api.EventStatus_ACTIVATE_SUCCESS,
			api.EventStatus_ACTIVATE_FAIL,
			api.EventStatus_VERIFY_SUCCESS,
			api.EventStatus_VERIFY_FAIL,
			api.EventStatus_IDENTITY_DELETED,
		}[Intn(9)],
		Error:   []string{"", prefix + "-" + String(10)}[Intn(2)],
		TraceId: uuid.NewString(),
	}
}
