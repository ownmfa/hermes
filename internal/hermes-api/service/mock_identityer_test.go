// Code generated by MockGen. DO NOT EDIT.
// Source: identity.go
//
// Generated by this command:
//
//	mockgen -source identity.go -destination mock_identityer_test.go -package service
//
// Package service is a generated GoMock package.
package service

import (
	context "context"
	reflect "reflect"
	time "time"

	api "github.com/ownmfa/api/go/api"
	oath "github.com/ownmfa/hermes/pkg/oath"
	gomock "go.uber.org/mock/gomock"
)

// MockIdentityer is a mock of Identityer interface.
type MockIdentityer struct {
	ctrl     *gomock.Controller
	recorder *MockIdentityerMockRecorder
}

// MockIdentityerMockRecorder is the mock recorder for MockIdentityer.
type MockIdentityerMockRecorder struct {
	mock *MockIdentityer
}

// NewMockIdentityer creates a new mock instance.
func NewMockIdentityer(ctrl *gomock.Controller) *MockIdentityer {
	mock := &MockIdentityer{ctrl: ctrl}
	mock.recorder = &MockIdentityerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockIdentityer) EXPECT() *MockIdentityerMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockIdentityer) Create(ctx context.Context, identity *api.Identity) (*api.Identity, *oath.OTP, bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", ctx, identity)
	ret0, _ := ret[0].(*api.Identity)
	ret1, _ := ret[1].(*oath.OTP)
	ret2, _ := ret[2].(bool)
	ret3, _ := ret[3].(error)
	return ret0, ret1, ret2, ret3
}

// Create indicates an expected call of Create.
func (mr *MockIdentityerMockRecorder) Create(ctx, identity any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockIdentityer)(nil).Create), ctx, identity)
}

// Delete mocks base method.
func (m *MockIdentityer) Delete(ctx context.Context, identityID, orgID, appID string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Delete", ctx, identityID, orgID, appID)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete.
func (mr *MockIdentityerMockRecorder) Delete(ctx, identityID, orgID, appID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockIdentityer)(nil).Delete), ctx, identityID, orgID, appID)
}

// List mocks base method.
func (m *MockIdentityer) List(ctx context.Context, orgID string, lBoundTS time.Time, prevID string, limit int32, appID string) ([]*api.Identity, int32, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", ctx, orgID, lBoundTS, prevID, limit, appID)
	ret0, _ := ret[0].([]*api.Identity)
	ret1, _ := ret[1].(int32)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// List indicates an expected call of List.
func (mr *MockIdentityerMockRecorder) List(ctx, orgID, lBoundTS, prevID, limit, appID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockIdentityer)(nil).List), ctx, orgID, lBoundTS, prevID, limit, appID)
}

// Read mocks base method.
func (m *MockIdentityer) Read(ctx context.Context, identityID, orgID, appID string) (*api.Identity, *oath.OTP, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Read", ctx, identityID, orgID, appID)
	ret0, _ := ret[0].(*api.Identity)
	ret1, _ := ret[1].(*oath.OTP)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Read indicates an expected call of Read.
func (mr *MockIdentityerMockRecorder) Read(ctx, identityID, orgID, appID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Read", reflect.TypeOf((*MockIdentityer)(nil).Read), ctx, identityID, orgID, appID)
}

// UpdateStatus mocks base method.
func (m *MockIdentityer) UpdateStatus(ctx context.Context, identityID, orgID, appID string, status api.IdentityStatus) (*api.Identity, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateStatus", ctx, identityID, orgID, appID, status)
	ret0, _ := ret[0].(*api.Identity)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateStatus indicates an expected call of UpdateStatus.
func (mr *MockIdentityerMockRecorder) UpdateStatus(ctx, identityID, orgID, appID, status any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateStatus", reflect.TypeOf((*MockIdentityer)(nil).UpdateStatus), ctx, identityID, orgID, appID, status)
}
//lint:file-ignore ST1000 Mockgen package comment
