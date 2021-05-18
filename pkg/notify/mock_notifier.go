// Code generated by MockGen. DO NOT EDIT.
// Source: notifier.go

// Package notify is a generated GoMock package.
package notify

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockNotifier is a mock of Notifier interface.
type MockNotifier struct {
	ctrl     *gomock.Controller
	recorder *MockNotifierMockRecorder
}

// MockNotifierMockRecorder is the mock recorder for MockNotifier.
type MockNotifierMockRecorder struct {
	mock *MockNotifier
}

// NewMockNotifier creates a new mock instance.
func NewMockNotifier(ctrl *gomock.Controller) *MockNotifier {
	mock := &MockNotifier{ctrl: ctrl}
	mock.recorder = &MockNotifierMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockNotifier) EXPECT() *MockNotifierMockRecorder {
	return m.recorder
}

// Email mocks base method.
func (m *MockNotifier) Email(ctx context.Context, displayName, appEmail, userEmail, subject, body string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Email", ctx, displayName, appEmail, userEmail, subject, body)
	ret0, _ := ret[0].(error)
	return ret0
}

// Email indicates an expected call of Email.
func (mr *MockNotifierMockRecorder) Email(ctx, displayName, appEmail, userEmail, subject, body interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Email", reflect.TypeOf((*MockNotifier)(nil).Email), ctx, displayName, appEmail, userEmail, subject, body)
}

// Pushover mocks base method.
func (m *MockNotifier) Pushover(ctx context.Context, userKey, subject, body string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Pushover", ctx, userKey, subject, body)
	ret0, _ := ret[0].(error)
	return ret0
}

// Pushover indicates an expected call of Pushover.
func (mr *MockNotifierMockRecorder) Pushover(ctx, userKey, subject, body interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Pushover", reflect.TypeOf((*MockNotifier)(nil).Pushover), ctx, userKey, subject, body)
}

// SMS mocks base method.
func (m *MockNotifier) SMS(ctx context.Context, phone, displayName, passcode string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SMS", ctx, phone, displayName, passcode)
	ret0, _ := ret[0].(error)
	return ret0
}

// SMS indicates an expected call of SMS.
func (mr *MockNotifierMockRecorder) SMS(ctx, phone, displayName, passcode interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SMS", reflect.TypeOf((*MockNotifier)(nil).SMS), ctx, phone, displayName, passcode)
}

// VaildatePushover mocks base method.
func (m *MockNotifier) VaildatePushover(ctx context.Context, userKey string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VaildatePushover", ctx, userKey)
	ret0, _ := ret[0].(error)
	return ret0
}

// VaildatePushover indicates an expected call of VaildatePushover.
func (mr *MockNotifierMockRecorder) VaildatePushover(ctx, userKey interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VaildatePushover", reflect.TypeOf((*MockNotifier)(nil).VaildatePushover), ctx, userKey)
}

// VaildateSMS mocks base method.
func (m *MockNotifier) VaildateSMS(ctx context.Context, phone string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VaildateSMS", ctx, phone)
	ret0, _ := ret[0].(error)
	return ret0
}

// VaildateSMS indicates an expected call of VaildateSMS.
func (mr *MockNotifierMockRecorder) VaildateSMS(ctx, phone interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VaildateSMS", reflect.TypeOf((*MockNotifier)(nil).VaildateSMS), ctx, phone)
}
