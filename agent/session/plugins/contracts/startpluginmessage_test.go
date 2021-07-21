// Copyright 2021 BastionZero Inc.

package contracts

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ErrOnUnmarshalUnknownPluginName(t *testing.T) {
	// Tests that unmarshaling a StartPluginMessage whose raw JSON has an
	// unknown plugin name, returns an errUnknownPluginName
	tests := map[string]struct {
		rawJson []byte
	}{
		"unknown plugin name": {
			rawJson: []byte(`
			{
				"PluginName": "FooBar"
			}
			`),
		},
		"unknown plugin name w/ unknown payload": {
			rawJson: []byte(`
			{
				"PluginName": "FooBar",
				"Payload":
				{
					"OptionA": true
				}
			}
			`),
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			var decoded StartPluginMessage
			var err error

			err = json.Unmarshal(test.rawJson, &decoded)
			require.True(t, errors.Is(err, errUnknownPluginName))
		})
	}
}

func Test_UnmarshalAndMarshalEquiv(t *testing.T) {
	// Tests that unmarshaling a StartPluginMessage from raw, valid Json-encoded
	// data to its respective Golang type t, and then marshaling t back to JSON
	// correctly matches the original JSON
	tests := map[string]struct {
		rawJson []byte
	}{
		"StartFud": {
			rawJson: []byte(`
			{
				"PluginName": "StartFud",
				"Payload": 
				{ 
					"TargetUser": "Foo"
				}
			}
			`),
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			var decoded StartPluginMessage
			var err error

			err = json.Unmarshal(test.rawJson, &decoded)
			require.NoError(t, err)
			reMarshaledRawJson, err := json.Marshal(decoded)
			require.NoError(t, err)
			require.JSONEq(t, string(test.rawJson), string(reMarshaledRawJson))
		})
	}
}
