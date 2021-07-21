// Copyright 2021 BastionZero Inc.
// Code generated using mockery 2.7.5

package mocks

import (
	contracts "github.com/aws/amazon-ssm-agent/agent/keysplitting/contracts"

	mock "github.com/stretchr/testify/mock"
)

// IKeysplittingHelper is an autogenerated mock type for the IKeysplittingHelper type
type IKeysplittingHelper struct {
	mock.Mock
}

// BuildDataAck provides a mock function with given fields: datapayload
func (_m *IKeysplittingHelper) BuildDataAck(datapayload contracts.DataPayload) error {
	ret := _m.Called(datapayload)

	var r0 error
	if rf, ok := ret.Get(0).(func(contracts.DataPayload) error); ok {
		r0 = rf(datapayload)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// BuildDataAckPayload provides a mock function with given fields: action, payload
func (_m *IKeysplittingHelper) BuildDataAckPayload(action contracts.KeysplittingAction, payload string) (contracts.DataAckPayload, error) {
	ret := _m.Called(action, payload)

	var r0 contracts.DataAckPayload
	if rf, ok := ret.Get(0).(func(contracts.KeysplittingAction, string) contracts.DataAckPayload); ok {
		r0 = rf(action, payload)
	} else {
		r0 = ret.Get(0).(contracts.DataAckPayload)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(contracts.KeysplittingAction, string) error); ok {
		r1 = rf(action, payload)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// BuildDataAckWithPayload provides a mock function with given fields: datapayload, payload
func (_m *IKeysplittingHelper) BuildDataAckWithPayload(datapayload contracts.DataPayload, payload string) error {
	ret := _m.Called(datapayload, payload)

	var r0 error
	if rf, ok := ret.Get(0).(func(contracts.DataPayload, string) error); ok {
		r0 = rf(datapayload, payload)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// BuildError provides a mock function with given fields: message, errortype
func (_m *IKeysplittingHelper) BuildError(message string, errortype contracts.KeysplittingErrorType) error {
	ret := _m.Called(message, errortype)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, contracts.KeysplittingErrorType) error); ok {
		r0 = rf(message, errortype)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// BuildSynAck provides a mock function with given fields: nonce, synpayload
func (_m *IKeysplittingHelper) BuildSynAck(nonce string, synpayload contracts.SynPayload) error {
	ret := _m.Called(nonce, synpayload)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, contracts.SynPayload) error); ok {
		r0 = rf(nonce, synpayload)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CheckBZECert provides a mock function with given fields: certHash
func (_m *IKeysplittingHelper) CheckBZECert(certHash string) error {
	ret := _m.Called(certHash)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(certHash)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetNonce provides a mock function with given fields:
func (_m *IKeysplittingHelper) GetNonce() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Hash provides a mock function with given fields: a
func (_m *IKeysplittingHelper) Hash(a interface{}) (string, error) {
	ret := _m.Called(a)

	var r0 string
	if rf, ok := ret.Get(0).(func(interface{}) string); ok {
		r0 = rf(a)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(interface{}) error); ok {
		r1 = rf(a)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// HashStruct provides a mock function with given fields: payload
func (_m *IKeysplittingHelper) HashStruct(payload interface{}) (string, error) {
	ret := _m.Called(payload)

	var r0 string
	if rf, ok := ret.Get(0).(func(interface{}) string); ok {
		r0 = rf(payload)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(interface{}) error); ok {
		r1 = rf(payload)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ProcessSyn provides a mock function with given fields: payload
func (_m *IKeysplittingHelper) ProcessSyn(payload []byte) error {
	ret := _m.Called(payload)

	var r0 error
	if rf, ok := ret.Get(0).(func([]byte) error); ok {
		r0 = rf(payload)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SignPayload provides a mock function with given fields: payload
func (_m *IKeysplittingHelper) SignPayload(payload interface{}) (string, error) {
	ret := _m.Called(payload)

	var r0 string
	if rf, ok := ret.Get(0).(func(interface{}) string); ok {
		r0 = rf(payload)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(interface{}) error); ok {
		r1 = rf(payload)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdateHPointer provides a mock function with given fields: rawpayload
func (_m *IKeysplittingHelper) UpdateHPointer(rawpayload interface{}) error {
	ret := _m.Called(rawpayload)

	var r0 error
	if rf, ok := ret.Get(0).(func(interface{}) error); ok {
		r0 = rf(rawpayload)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ValidateDataMessage provides a mock function with given fields: payload
func (_m *IKeysplittingHelper) ValidateDataMessage(payload []byte) (contracts.DataPayload, error) {
	ret := _m.Called(payload)

	var r0 contracts.DataPayload
	if rf, ok := ret.Get(0).(func([]byte) contracts.DataPayload); ok {
		r0 = rf(payload)
	} else {
		r0 = ret.Get(0).(contracts.DataPayload)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func([]byte) error); ok {
		r1 = rf(payload)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// VerifyBZECert provides a mock function with given fields: cert
func (_m *IKeysplittingHelper) VerifyBZECert(cert contracts.BZECert) error {
	ret := _m.Called(cert)

	var r0 error
	if rf, ok := ret.Get(0).(func(contracts.BZECert) error); ok {
		r0 = rf(cert)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// VerifyHPointer provides a mock function with given fields: newPointer
func (_m *IKeysplittingHelper) VerifyHPointer(newPointer string) error {
	ret := _m.Called(newPointer)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(newPointer)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// VerifySignature provides a mock function with given fields: payload, sig, bzehash
func (_m *IKeysplittingHelper) VerifySignature(payload interface{}, sig string, bzehash string) error {
	ret := _m.Called(payload, sig, bzehash)

	var r0 error
	if rf, ok := ret.Get(0).(func(interface{}, string, string) error); ok {
		r0 = rf(payload, sig, bzehash)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// VerifyTargetId provides a mock function with given fields: targetid
func (_m *IKeysplittingHelper) VerifyTargetId(targetid string) error {
	ret := _m.Called(targetid)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(targetid)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
