// Copyright 2021 BastionZero Inc.

package contracts

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Errors
var (
	errUnknownPluginName = errors.New("unmarshal PluginName: unknown plugin name")
)

type PluginName string

// Enumerations of all valid "PluginName" fields
const (
	// StartFud indicates that the FUD plugin should be activated
	StartFud PluginName = "StartFud"
)

type PluginNameSwitch struct {
	PluginName string `json:"PluginName"`
}

type StartPluginMessage struct {
	PluginNameSwitch
	Payload interface{} `json:"Payload"`
}

func (s *StartPluginMessage) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &s.PluginNameSwitch); err != nil {
		return err
	}
	switch s.PluginName {
	case string(StartFud):
		s.Payload = new(StartFUDCommand)
	default:
		return fmt.Errorf("%w: %v", errUnknownPluginName, s.PluginName)
	}

	// Source: https://stackoverflow.com/a/53454226
	type tmp StartPluginMessage
	return json.Unmarshal(data, (*tmp)(s))
}

type StartFUDCommand struct {
	TargetUser string `json:"TargetUser"`
}
