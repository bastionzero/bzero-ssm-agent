// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

// Package sessionplugin implements functionality common to all session manager plugins
package sessionplugin

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"regexp"

	"github.com/aws/amazon-ssm-agent/agent/jsonutil"
	"github.com/aws/amazon-ssm-agent/agent/log"

	"github.com/aws/amazon-ssm-agent/agent/appconfig"
	"github.com/aws/amazon-ssm-agent/agent/context"
	"github.com/aws/amazon-ssm-agent/agent/contracts"
	"github.com/aws/amazon-ssm-agent/agent/framework/processor/executer/iohandler"
	mgsConfig "github.com/aws/amazon-ssm-agent/agent/session/config"
	mgsContracts "github.com/aws/amazon-ssm-agent/agent/session/contracts"
	"github.com/aws/amazon-ssm-agent/agent/session/datachannel"
	pluginContracts "github.com/aws/amazon-ssm-agent/agent/session/plugins/contracts"
	"github.com/aws/amazon-ssm-agent/agent/session/plugins/fileuploaddownload"
	"github.com/aws/amazon-ssm-agent/agent/session/retry"
	"github.com/aws/amazon-ssm-agent/agent/task"
)

type NewPluginFunc func(context.T) (ISessionPlugin, error)

// ISessionPlugin interface represents functions that need to be implemented by all session manager plugins
type ISessionPlugin interface {
	GetPluginParameters(parameters interface{}) interface{}
	RequireHandshake() bool
	Execute(config contracts.Configuration, cancelFlag task.CancelFlag, output iohandler.IOHandler, dataChannel datachannel.IDataChannel)
	InputStreamMessageHandler(log log.T, streamDataMessage mgsContracts.AgentMessage) error
}

// SessionPlugin is the wrapper for all session manager plugins and implements all functions of Runpluginutil.T interface
type SessionPlugin struct {
	context       context.T
	sessionPlugin ISessionPlugin
}

// NewPlugin returns a new instance of SessionPlugin which wraps a plugin that implements ISessionPlugin
func NewPlugin(context context.T, newPluginFunc NewPluginFunc) (*SessionPlugin, error) {
	sessionPlugin, err := newPluginFunc(context)
	return &SessionPlugin{context, sessionPlugin}, err
}

// Execute sets up datachannel and starts execution of session manager plugin like shell
func (p *SessionPlugin) Execute(
	config contracts.Configuration,
	cancelFlag task.CancelFlag,
	output iohandler.IOHandler) {

	if config.PluginName == appconfig.PluginNameInteractiveCommands {
		var shellProps mgsContracts.ShellProperties
		err := jsonutil.Remarshal(config.Properties, &shellProps)
		if err != nil {
			errorString := fmt.Errorf("Session id %v: Invalid format in session properties %v;\nerror %v", config.SessionId, config.Properties, err)
			output.MarkAsFailed(errorString)
			p.context.Log().Error(errorString)
			return
		}

		// Check if we should run FUD. All FUD activations have a JSON encoded
		// StartPluginMessage struct in the .Commands field of the shell
		// properties.
		var startPluginMsg pluginContracts.StartPluginMessage
		if err := json.Unmarshal([]byte(shellProps.Linux.Commands), &startPluginMsg); err == nil {
			if startPluginMsg.PluginName == string(pluginContracts.StartFud) {
				payload := startPluginMsg.Payload.(*pluginContracts.StartFUDCommand)
				targetUser := payload.TargetUser
				p.context = p.context.ChangePluginNameTo(appconfig.PluginNameFileUploadDownload)
				fud, err := fileuploaddownload.NewPlugin(p.context, targetUser)
				if err != nil {
					errorString := fmt.Errorf("Session id %v: Failed to create FUD plugin: %v", config.SessionId, err)
					output.MarkAsFailed(errorString)
					p.context.Log().Error(errorString)
					return
				}
				// Change to FUD plugin
				p.sessionPlugin = fud
			}
		} else {
			// If StartPluginMessage not found in shellProps.Commands, then we
			// assume shellProps.Commands contains a literal command string
			// meant to be passed to the PTY (created by the InteractiveCommands
			// plugin) as an initial command.

			// Require any startup commands to follow strict rules
			// "sudo su {TargetUser} -l"
			// https://unix.stackexchange.com/a/435120 for username matching in regex below
			exp := "^sudo su [a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\\$) -l$"
			r, _ := regexp.Compile(exp)
			if !r.MatchString(shellProps.Linux.Commands) {
				errorString := fmt.Errorf("Setting up data channel with id %s failed because an incorrect command attempted to execute", config.SessionId)
				output.MarkAsFailed(errorString)
				p.context.Log().Error(errorString)
				return
			}
		}
	}

	log := p.context.Log()
	kmsKeyId := config.KmsKeyId

	dataChannel, err := getDataChannelForSessionPlugin(p.context, config.SessionId, config.ClientId, cancelFlag, p.sessionPlugin.InputStreamMessageHandler)
	if err != nil {
		errorString := fmt.Errorf("Setting up data channel with id %s failed: %s", config.SessionId, err)
		output.MarkAsFailed(errorString)
		log.Error(errorString)
		return
	}

	defer func() {
		dataChannel.PrepareToCloseChannel(log)
		dataChannel.Close(log)
	}()

	if err = dataChannel.SendAgentSessionStateMessage(p.context.Log(), mgsContracts.Connected); err != nil {
		log.Errorf("Unable to send AgentSessionState message with session status %s. %s", mgsContracts.Connected, err)
	}

	encryptionEnabled := p.isEncryptionEnabled(kmsKeyId, config.PluginName)
	sessionTypeRequest := mgsContracts.SessionTypeRequest{
		SessionType: config.PluginName,
		Properties:  p.sessionPlugin.GetPluginParameters(config.Properties),
	}
	if p.sessionPlugin.RequireHandshake() || encryptionEnabled {
		if err = dataChannel.PerformHandshake(log, kmsKeyId, encryptionEnabled, sessionTypeRequest); err != nil {
			errorString := fmt.Errorf("Encountered error while initiating handshake. %s", err)
			output.MarkAsFailed(errorString)
			log.Error(errorString)
			return
		}
	} else {
		dataChannel.SkipHandshake(log)
	}

	p.sessionPlugin.Execute(config, cancelFlag, output, dataChannel)
}

// isEncryptionEnabled checks kmsKeyId and pluginName to determine if encryption is enabled for this session
// TODO: make encryption configurable for port plugin
func (p *SessionPlugin) isEncryptionEnabled(kmsKeyId string, pluginName string) bool {
	return kmsKeyId != "" && pluginName != appconfig.PluginNamePort
}

// getDataChannelForSessionPlugin opens new data channel to MGS service
var getDataChannelForSessionPlugin = func(context context.T, sessionId string, clientId string, cancelFlag task.CancelFlag, inputStreamMessageHandler datachannel.InputStreamMessageHandler) (datachannel.IDataChannel, error) {
	retryer := retry.ExponentialRetryer{
		CallableFunc: func() (channel interface{}, err error) {
			return datachannel.NewDataChannel(
				context,
				sessionId,
				clientId,
				inputStreamMessageHandler,
				cancelFlag)
		},
		GeometricRatio:      mgsConfig.RetryGeometricRatio,
		InitialDelayInMilli: rand.Intn(mgsConfig.DataChannelRetryInitialDelayMillis) + mgsConfig.DataChannelRetryInitialDelayMillis,
		MaxDelayInMilli:     mgsConfig.DataChannelRetryMaxIntervalMillis,
		MaxAttempts:         mgsConfig.DataChannelNumMaxAttempts,
	}
	channel, err := retryer.Call()
	if err != nil {
		return nil, err
	}
	dataChannel := channel.(*datachannel.DataChannel)
	return dataChannel, nil
}
