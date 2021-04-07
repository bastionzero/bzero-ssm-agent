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
	"encoding/json"
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
	ksHelper    keysplitting.KeysplittingHelper
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
	log.Infof("[Keysplitting] Message received by StandardStream with payload %v", streamDataMessage.PayloadType)
	switch mgsContracts.PayloadType(streamDataMessage.PayloadType) {

	case mgsContracts.Syn:
		log.Infof("[Keysplitting] Syn Payload Received: %v", string(streamDataMessage.Payload))

		var synpayload kysplContracts.SynPayload
		if err := json.Unmarshal(streamDataMessage.Payload, &synpayload); err != nil {
			// not a keysplitting error, also we can't possibly have the hpointer so it wouldn't be possible to associate the error with the correct message
			message := fmt.Sprintf("Error occurred while parsing SynPayload json: %v", err)
			// Is it icky that anyone can send a Syn or Data payload and get back the current state of the hpointer? Am I overreacting? -lucie
			return p.ksHelper.BuildError(message, kysplContracts.InvalidPayload)
		}
		log.Infof("[Keysplitting] Syn Payload Unmarshalled")

		// Get nonce either rand or hpointer (if there is one)
		nonce := p.ksHelper.GetNonce()

		// Update hpointer so we have it for the error messages
		if err := p.ksHelper.UpdateHPointer(synpayload.Payload); err != nil {
			return err
		}

		// pretty legit BZECert verification
		if err := p.ksHelper.VerifyBZECert(synpayload.Payload.BZECert); err != nil {
			return err
		}

		// Client Signature verification
		bzehash, _ := keysplitting.HashStruct(synpayload.Payload.BZECert)
		if err := p.ksHelper.VerifySignature(synpayload.Payload, synpayload.Signature, bzehash); err != nil {
			return err
		}
		log.Infof("[Keysplitting] Client Signature on Syn Message Verified")

		// Validate that TargetId == Hash(pubkey)
		if err := p.ksHelper.VerifyTargetId(synpayload.Payload.TargetId); err != nil {
			return err
		}
		log.Infof("[Keysplitting] TargetID from Syn Message Verified")

		// Tells parent Datachannel object to send SYNACK message with specified payload
		log.Infof("[Keysplitting] Sending SynAck Message...")
		return p.ksHelper.BuildSynAck(nonce, synpayload)

	case mgsContracts.Data:
		log.Infof("[Keysplitting] Data Payload Received: %v", string(streamDataMessage.Payload))

		var datapayload kysplContracts.DataPayload
		if err := json.Unmarshal(streamDataMessage.Payload, &datapayload); err != nil {
			message := fmt.Sprintf("[Keysplitting] Error occurred while parsing DataPayload json: %v", err)
			return p.ksHelper.BuildError(message, kysplContracts.InvalidPayload)
		}
		log.Infof("[Keysplitting] Data Payload Unmarshalled...")

		// Update hpointer, needs to be done asap for error reporting purposes
		if err := p.ksHelper.UpdateHPointer(datapayload.Payload); err != nil {
			return err
		}

		// Make sure BZECert hash matches existing hash
		// In the future we should be getting a hash here that we can easily lookup in the map
		if err := p.ksHelper.CheckBZECert(datapayload.Payload.BZECert); err != nil {
			return err
		}

		// Verify client signature
		// if err := p.ksHelper.VerifySignature(datapayload.Payload, datapayload.Signature, datapayload.Payload.BZECert); err != nil {
		// 	return err
		// }
		log.Infof("[Keysplitting] Client Signature on Data Message Verified")

		// Validate hash pointer
		// if err := p.ksHelper.VerifyHPointer(datapayload.Payload.HPointer); err != nil {
		// 	return err
		// }

		// Validate that TargetId == Hash(pubkey)
		if err := p.ksHelper.VerifyTargetId(datapayload.Payload.TargetId); err != nil {
			return err
		}
		log.Infof("[Keysplitting] TargetID from Data Message Verified")

		// Do something with action
		switch datapayload.Payload.Action {
		case string(kysplContracts.ShellOpen):
			p.channelOpen = true
			log.Infof("[Keysplitting] shell/open Action Completed")
		case string(kysplContracts.ShellClose):
			p.channelOpen = false
			log.Infof("[Keysplitting] shell/close Action Completed")
		default:
			message := fmt.Sprintf("[Keysplitting] Keysplitting Action Not Recognized: %v", datapayload.Payload.Action)
			return p.ksHelper.BuildError(message, kysplContracts.KeysplittingActionError)
		}

		// Tells parent Datachannel object to send DATAACK message with specified payload
		log.Infof("[Keysplitting] Sending DataAck Message...")
		return p.ksHelper.BuildDataAck(datapayload)

	default:
		// if p.channelOpen {
		// 	return p.shell.InputStreamMessageHandler(log, streamDataMessage)
		// } else {
		// 	message := fmt.Sprintf("[Keysplitting] Keysplitting Handshake is required to communicate with shell: %v", datapayload.Payload.Action)
		// 	return p.ksHelper.BuildError(message, kysplContracts.ChannelClosed)
		// }
		return p.shell.InputStreamMessageHandler(log, streamDataMessage)
	}
}
