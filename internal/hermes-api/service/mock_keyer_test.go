// Code generated by MockGen. DO NOT EDIT.
// Source: session.go

// Package service is a generated GoMock package.
package service

import (
	context "context"
	reflect "reflect"
	time "time"

	api "github.com/ownmfa/api/go/api"
	gomock "go.uber.org/mock/gomock"
)

// MockKeyer is a mock of Keyer interface.
type MockKeyer struct {
	ctrl     *gomock.Controller
	recorder *MockKeyerMockRecorder
}

// MockKeyerMockRecorder is the mock recorder for MockKeyer.
type MockKeyerMockRecorder struct {
	mock *MockKeyer
}

// NewMockKeyer creates a new mock instance.
func NewMockKeyer(ctrl *gomock.Controller) *MockKeyer {
	mock := &MockKeyer{ctrl: ctrl}
	mock.recorder = &MockKeyerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockKeyer) EXPECT() *MockKeyerMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockKeyer) Create(ctx context.Context, key *api.Key) (*api.Key, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", ctx, key)
	ret0, _ := ret[0].(*api.Key)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Create indicates an expected call of Create.
func (mr *MockKeyerMockRecorder) Create(ctx, key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockKeyer)(nil).Create), ctx, key)
}

// Delete mocks base method.
func (m *MockKeyer) Delete(ctx context.Context, keyID, orgID string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Delete", ctx, keyID, orgID)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete.
func (mr *MockKeyerMockRecorder) Delete(ctx, keyID, orgID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockKeyer)(nil).Delete), ctx, keyID, orgID)
}

// List mocks base method.
func (m *MockKeyer) List(ctx context.Context, orgID string, lBoundTS time.Time, prevID string, limit int32) ([]*api.Key, int32, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", ctx, orgID, lBoundTS, prevID, limit)
	ret0, _ := ret[0].([]*api.Key)
	ret1, _ := ret[1].(int32)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// List indicates an expected call of List.
func (mr *MockKeyerMockRecorder) List(ctx, orgID, lBoundTS, prevID, limit interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockKeyer)(nil).List), ctx, orgID, lBoundTS, prevID, limit)
}
