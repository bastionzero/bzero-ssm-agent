// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may not
// use this file except in compliance with the License. A copy of the
// License is located at
//
// http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
// either express or implied. See the License for the specific language governing
// permissions and limitations under the License.

// Package interactivecommands implements session shell plugin with interactive commands.
package interactivecommands

import (
	"errors"
	"fmt"

	"github.com/aws/amazon-ssm-agent/agent/appconfig"
	"github.com/aws/amazon-ssm-agent/agent/context"
	agentContracts "github.com/aws/amazon-ssm-agent/agent/contracts"
	"github.com/aws/amazon-ssm-agent/agent/framework/processor/executer/iohandler"
	"github.com/aws/amazon-ssm-agent/agent/keysplitting"
	kysplContracts "github.com/aws/amazon-ssm-agent/agent/keysplitting/contracts"
	"github.com/aws/amazon-ssm-agent/agent/log"
	mgsContracts "github.com/aws/amazon-ssm-agent/agent/session/contracts"
	"github.com/aws/amazon-ssm-agent/agent/session/datachannel"
	"github.com/aws/amazon-ssm-agent/agent/session/plugins/sessionplugin"
	"github.com/aws/amazon-ssm-agent/agent/session/plugins/singlecommand"
	"github.com/aws/amazon-ssm-agent/agent/task"
)

// InteractiveCommandsPlugin is the type for the sessionPlugin.
type InteractiveCommandsPlugin struct {
	context       context.T
	sessionPlugin sessionplugin.ISessionPlugin
	channelOpen   bool
	ksHelper      keysplitting.IKeysplittingHelper
}

// Returns parameters required for CLI/console to start session
func (p *InteractiveCommandsPlugin) GetPluginParameters(parameters interface{}) interface{} {
	return p.sessionPlugin.GetPluginParameters(parameters)
}

// InteractiveCommands plugin doesn't require handshake to establish session
func (p *InteractiveCommandsPlugin) RequireHandshake() bool {
	return p.sessionPlugin.RequireHandshake()
}

// NewPlugin returns a new instance of the InteractiveCommands Plugin
func NewPlugin(context context.T) (sessionplugin.ISessionPlugin, error) {
	singleCommandPlugin, err := singlecommand.NewPlugin(context, appconfig.PluginNameInteractiveCommands)
	if err != nil {
		return nil, err
	}

	log := context.Log()
	if helper, err := keysplitting.Init(log); err == nil {
		var plugin = InteractiveCommandsPlugin{
			context:       context,
			sessionPlugin: singleCommandPlugin,
			channelOpen:   false,
			ksHelper:      helper,
		}
		return &plugin, nil
	} else {
		return nil, err
	}
}

// name returns the name of interactive commands Plugin
func (p *InteractiveCommandsPlugin) name() string {
	return appconfig.PluginNameInteractiveCommands
}

// Execute executes command as passed in from document parameter via pty.stdin.
// It reads message from cmd.stdout and writes to data channel.
func (p *InteractiveCommandsPlugin) Execute(config agentContracts.Configuration,
	cancelFlag task.CancelFlag,
	output iohandler.IOHandler,
	dataChannel datachannel.IDataChannel) {

	p.sessionPlugin.Execute(config, cancelFlag, output, dataChannel)
}

// InputStreamMessageHandler passes payload byte stream to shell stdin
func (p *InteractiveCommandsPlugin) InputStreamMessageHandler(log log.T, streamDataMessage mgsContracts.AgentMessage) error {
	log.Infof("[Keysplitting] %v Message received by InteractiveCommands", mgsContracts.PayloadType(streamDataMessage.PayloadType))
	switch mgsContracts.PayloadType(streamDataMessage.PayloadType) {

	case mgsContracts.Syn:
		return p.ksHelper.ProcessSyn(streamDataMessage.Payload)

	case mgsContracts.Data:
		// Process actions
		if datapayload, err := p.ksHelper.ValidateDataMessage(streamDataMessage.Payload); err == nil {

			switch kysplContracts.KeysplittingAction(datapayload.Payload.Action) {

			case kysplContracts.ShellOpen:
				p.channelOpen = true
				log.Infof("[Keysplitting] shell/open Action Completed")

			case kysplContracts.ShellClose:
				p.channelOpen = false
				log.Infof("[Keysplitting] shell/close Action Completed")

			case kysplContracts.ShellInput:
				if err := p.forwardMessage(log, streamDataMessage, mgsContracts.Output, datapayload.Payload); err != nil {
					return err
				}

			case kysplContracts.ShellResize:
				if err := p.forwardMessage(log, streamDataMessage, mgsContracts.Size, datapayload.Payload); err != nil {
					return err
				}
				log.Infof("[Keysplitting] shell/resize Action Completed")

			default:
				message := fmt.Sprintf("Keysplitting Action Not Recognized: %v", datapayload.Payload.Action)
				return p.ksHelper.BuildError(message, kysplContracts.KeysplittingActionError)
			}

			// Tells parent Datachannel object to send DATAACK message with specified payload
			log.Infof("[Keysplitting] Sending DataAck Message...")
			return p.ksHelper.BuildDataAck(datapayload)
		} else {
			return err
		}

	// For backwards compatability, we will accept OG terminal resizing messages, but ignore them
	case mgsContracts.Size:
		return nil

	case mgsContracts.Output:
		// Ignore keep alive messages
		if len(streamDataMessage.Payload) == 0 {
			return nil
		} else { // OG way to communicate with shell, so we want to output correct error message
			message := fmt.Sprintf("This Agent requires a correctly formatted Keysplitting message to communicate with the shell")
			return p.ksHelper.BuildError(message, kysplContracts.InvalidPayload)
		}

	default: // fail secure
		message := fmt.Sprintf("This Agent requires a correctly formatted Keysplitting message to communicate with the shell")
		return p.ksHelper.BuildError(message, kysplContracts.InvalidPayload)
	}
}

// shell message function only processes two kinds of messages: Output (for shell input) and Size (for terminal resizing)
func (p *InteractiveCommandsPlugin) forwardMessage(log log.T, streamDataMessage mgsContracts.AgentMessage, payloadtype mgsContracts.PayloadType, payload kysplContracts.DataPayloadPayload) error {
	if p.channelOpen {
		agentMessage := mgsContracts.AgentMessage{
			MessageType: streamDataMessage.MessageType,
			Payload:     []byte(payload.Payload), // a string for Output or a json {cols: x, rows: y} for Size
			PayloadType: uint32(payloadtype),     // either Output or Size
		}

		err := p.sessionPlugin.InputStreamMessageHandler(log, agentMessage)
		if errors.Is(err, mgsContracts.ErrHandlerNotReady) {
			message := "Shell not yet ready for incoming messages"
			return p.ksHelper.BuildError(message, kysplContracts.HandlerNotReady)
		} else {
			return err
		}
	} else {
		message := fmt.Sprintf("[Keysplitting] Keysplitting Handshake is required to communicate with shell")
		return p.ksHelper.BuildError(message, kysplContracts.ChannelClosed)
	}
}
