// Code generated by MockGen. DO NOT EDIT.
// Source: proto_test.go
//
// Generated by this command:
//
//	mockgen -source proto_test.go -destination mock_protoer_test.go -package matcher
//
// Package matcher is a generated GoMock package.
package matcher

import (
	reflect "reflect"

	token "github.com/ownmfa/hermes/api/go/token"
	gomock "go.uber.org/mock/gomock"
)

// Mockprotoer is a mock of protoer interface.
type Mockprotoer struct {
	ctrl     *gomock.Controller
	recorder *MockprotoerMockRecorder
}

// MockprotoerMockRecorder is the mock recorder for Mockprotoer.
type MockprotoerMockRecorder struct {
	mock *Mockprotoer
}

// NewMockprotoer creates a new mock instance.
func NewMockprotoer(ctrl *gomock.Controller) *Mockprotoer {
	mock := &Mockprotoer{ctrl: ctrl}
	mock.recorder = &MockprotoerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *Mockprotoer) EXPECT() *MockprotoerMockRecorder {
	return m.recorder
}

// f mocks base method.
func (m *Mockprotoer) f(vIn *token.Web) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "f", vIn)
	ret0, _ := ret[0].(error)
	return ret0
}

// f indicates an expected call of f.
func (mr *MockprotoerMockRecorder) f(vIn any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "f", reflect.TypeOf((*Mockprotoer)(nil).f), vIn)
}
//lint:file-ignore ST1000 Mockgen package comment
