// Automatically generated by MockGen. DO NOT EDIT!
// Source: client/clientDb_I.go

package client

import (
	gomock "github.com/golang/mock/gomock"
)

// Mock of ClientDb_I interface
type MockClientDb_I struct {
	ctrl     *gomock.Controller
	recorder *_MockClientDb_IRecorder
}

// Recorder for MockClientDb_I (not exported)
type _MockClientDb_IRecorder struct {
	mock *MockClientDb_I
}

func NewMockClientDb_I(ctrl *gomock.Controller) *MockClientDb_I {
	mock := &MockClientDb_I{ctrl: ctrl}
	mock.recorder = &_MockClientDb_IRecorder{mock}
	return mock
}

func (_m *MockClientDb_I) EXPECT() *_MockClientDb_IRecorder {
	return _m.recorder
}

func (_m *MockClientDb_I) VerifyClient(c Client) error {
	ret := _m.ctrl.Call(_m, "VerifyClient", c)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockClientDb_IRecorder) VerifyClient(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "VerifyClient", arg0)
}
