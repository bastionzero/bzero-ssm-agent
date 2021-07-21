// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Modifications Copyright 2021 BastionZero Inc.
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
	"fmt"

	"github.com/aws/amazon-ssm-agent/agent/appconfig"
	"github.com/aws/amazon-ssm-agent/agent/context"
	agentContracts "github.com/aws/amazon-ssm-agent/agent/contracts"
	"github.com/aws/amazon-ssm-agent/agent/framework/processor/executer/iohandler"
	"github.com/aws/amazon-ssm-agent/agent/jsonutil"
	"github.com/aws/amazon-ssm-agent/agent/keysplitting"
	kysplContracts "github.com/aws/amazon-ssm-agent/agent/keysplitting/contracts"
	"github.com/aws/amazon-ssm-agent/agent/log"
	mgsContracts "github.com/aws/amazon-ssm-agent/agent/session/contracts"
	"github.com/aws/amazon-ssm-agent/agent/session/datachannel"
	"github.com/aws/amazon-ssm-agent/agent/session/plugins/sessionplugin"
	"github.com/aws/amazon-ssm-agent/agent/session/shell"
	"github.com/aws/amazon-ssm-agent/agent/task"
)

// InteractiveCommandsPlugin is the type for the plugin.
type InteractiveCommandsPlugin struct {
	context     context.T
	shell       shell.IShellPlugin
	channelOpen bool
	ksHelper    keysplitting.IKeysplittingHelper
}

// Returns parameters required for CLI/console to start session
func (p *InteractiveCommandsPlugin) GetPluginParameters(parameters interface{}) interface{} {
	return nil
}

// InteractiveCommands plugin doesn't require handshake to establish session
func (p *InteractiveCommandsPlugin) RequireHandshake() bool {
	return false
}

// NewPlugin returns a new instance of the Interactive Commands Plugin
func NewPlugin(context context.T) (sessionplugin.ISessionPlugin, error) {
	shellPlugin, err := shell.NewPlugin(context, appconfig.PluginNameInteractiveCommands)
	if err != nil {
		return nil, err
	}

	log := context.Log()
	if helper, err := keysplitting.Init(log); err == nil {
		var plugin = InteractiveCommandsPlugin{
			context:     context,
			shell:       shellPlugin,
			channelOpen: false,
			ksHelper:    helper,
		}
		return &plugin, nil
	} else {
		return nil, err
	}
}

// name returns the name of Interactive commands Plugin
func (p *InteractiveCommandsPlugin) name() string {
	return appconfig.PluginNameInteractiveCommands
}

// Execute starts pseudo terminal.
// It reads incoming message from data channel and writes to pty.stdin.
// It reads message from pty.stdout and writes to data channel
func (p *InteractiveCommandsPlugin) Execute(
	config agentContracts.Configuration,
	cancelFlag task.CancelFlag,
	output iohandler.IOHandler,
	dataChannel datachannel.IDataChannel) {

	logger := p.context.Log()
	var shellProps mgsContracts.ShellProperties
	err := jsonutil.Remarshal(config.Properties, &shellProps)
	logger.Debugf("Plugin properties %v", shellProps)
	if err != nil {
		sessionPluginResultOutput := mgsContracts.SessionPluginResultOutput{}
		output.SetExitCode(appconfig.ErrorExitCode)
		output.SetStatus(agentContracts.ResultStatusFailed)
		sessionPluginResultOutput.Output = fmt.Sprintf("Invalid format in session properties %v;\nerror %v", config.Properties, err)
		output.SetOutput(sessionPluginResultOutput)
		logger.Error(sessionPluginResultOutput.Output)
		return
	}

	if err := p.validateProperties(shellProps); err != nil {
		sessionPluginResultOutput := mgsContracts.SessionPluginResultOutput{}
		output.SetExitCode(appconfig.ErrorExitCode)
		output.SetStatus(agentContracts.ResultStatusFailed)
		sessionPluginResultOutput.Output = err.Error()
		output.SetOutput(sessionPluginResultOutput)
		logger.Error(sessionPluginResultOutput.Output)
		return
	}

	// streaming of logs is not supported for interactive commands scenario, set it to false
	config.CloudWatchStreamingEnabled = false

	p.shell.Execute(config, cancelFlag, output, dataChannel, shellProps)
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

		if p.shell.Ready() {
			return p.shell.InputStreamMessageHandler(log, agentMessage)
		} else {
			message := "Shell not yet ready for incoming messages"
			return p.ksHelper.BuildError(message, kysplContracts.HandlerNotReady)
		}
	} else {
		message := fmt.Sprintf("[Keysplitting] Keysplitting Handshake is required to communicate with shell")
		return p.ksHelper.BuildError(message, kysplContracts.ChannelClosed)
	}
}
