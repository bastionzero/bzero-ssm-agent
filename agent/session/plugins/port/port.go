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

// Package port implements session manager's port plugin
package port

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/aws/amazon-ssm-agent/agent/appconfig"
	"github.com/aws/amazon-ssm-agent/agent/context"
	agentContracts "github.com/aws/amazon-ssm-agent/agent/contracts"
	"github.com/aws/amazon-ssm-agent/agent/framework/processor/executer/iohandler"
	"github.com/aws/amazon-ssm-agent/agent/jsonutil"
	"github.com/aws/amazon-ssm-agent/agent/keysplitting"
	"github.com/aws/amazon-ssm-agent/agent/log"
	mgsConfig "github.com/aws/amazon-ssm-agent/agent/session/config"
	mgsContracts "github.com/aws/amazon-ssm-agent/agent/session/contracts"
	"github.com/aws/amazon-ssm-agent/agent/session/datachannel"
	"github.com/aws/amazon-ssm-agent/agent/session/plugins/sessionplugin"
	"github.com/aws/amazon-ssm-agent/agent/task"
	"github.com/aws/amazon-ssm-agent/agent/versionutil"
)

const muxSupportedClientVersion = "1.1.70"

// PortParameters contains inputs required to execute port plugin.
type PortParameters struct {
	PortNumber string `json:"portNumber" yaml:"portNumber"`
	Type       string `json:"type"`
}

// Plugin is the type for the port plugin.
type PortPlugin struct {
	context     context.T
	dataChannel datachannel.IDataChannel
	cancelled   chan struct{}
	session     IPortSession
	ksHelper    keysplitting.KeysplittingHelper
}

// IPortSession interface represents functions that need to be implemented by all port sessions
type IPortSession interface {
	InitializeSession() (err error)
	HandleStreamMessage(streamDataMessage mgsContracts.AgentMessage) (err error)
	WritePump(channel datachannel.IDataChannel) (errorCode int)
	IsConnectionAvailable() (isAvailable bool)
	Stop()
}

// GetSession initializes session based on the type of the port session
// mux for port forwarding session and if client supports multiplexing; basic otherwise
var GetSession = func(context context.T, portParameters PortParameters, cancelled chan struct{}, clientVersion string, sessionId string) (session IPortSession, err error) {
	if portParameters.Type == mgsConfig.LocalPortForwarding &&
		versionutil.Compare(clientVersion, muxSupportedClientVersion, true) >= 0 {

		if session, err = NewMuxPortSession(context, cancelled, portParameters.PortNumber, sessionId); err == nil {
			return session, nil
		}
	} else {
		if session, err = NewBasicPortSession(context, cancelled, portParameters.PortNumber, portParameters.Type); err == nil {
			return session, nil
		}
	}
	return nil, err
}

// Returns parameters required for CLI to start session
func (p *PortPlugin) GetPluginParameters(parameters interface{}) interface{} {
	return parameters
}

// Port plugin requires handshake to establish session
func (p *PortPlugin) RequireHandshake() bool {
	return true
}

// NewPortPlugin returns a new instance of the Port Plugin.
func NewPlugin(context context.T) (sessionplugin.ISessionPlugin, error) {
	log := context.Log()
	if helper, err := keysplitting.Init(log); err == nil {
		var plugin = PortPlugin{
			context:   context,
			cancelled: make(chan struct{}),
			ksHelper:  helper,
		}
		return &plugin, nil
	} else {
		return &PortPlugin{}, err
	}
}

// Name returns the name of Port Plugin
func (p *PortPlugin) name() string {
	return appconfig.PluginNamePort
}

// Execute establishes a connection to a specified port from the parameters
// It reads incoming messages from the data channel and writes to the port
// It reads from the port and writes to the data channel
func (p *PortPlugin) Execute(
	config agentContracts.Configuration,
	cancelFlag task.CancelFlag,
	output iohandler.IOHandler,
	dataChannel datachannel.IDataChannel) {

	log := p.context.Log()
	p.dataChannel = dataChannel
	defer func() {
		if err := recover(); err != nil {
			log.Errorf("Error occurred while executing plugin %s: \n%v", p.name(), err)
			log.Errorf("Stacktrace:\n%s", debug.Stack())
			os.Exit(1)
		}
	}()

	if cancelFlag.ShutDown() {
		output.MarkAsShutdown()
	} else if cancelFlag.Canceled() {
		output.MarkAsCancelled()
	} else {
		p.execute(config, cancelFlag, output)
	}
}

// Execute establishes a connection to a specified port from the parameters
// It reads incoming messages from the data channel and writes to the port
// It reads from the port and writes to the data channel
func (p *PortPlugin) execute(
	config agentContracts.Configuration,
	cancelFlag task.CancelFlag,
	output iohandler.IOHandler) {

	log := p.context.Log()
	var err error
	sessionPluginResultOutput := mgsContracts.SessionPluginResultOutput{}

	defer func() {
		p.stop()
	}()

	if err = p.initializeParameters(config); err != nil {
		log.Error(err)
		output.SetExitCode(appconfig.ErrorExitCode)
		output.SetStatus(agentContracts.ResultStatusFailed)
		sessionPluginResultOutput.Output = err.Error()
		output.SetOutput(sessionPluginResultOutput)
		return
	}

	if err = p.session.InitializeSession(); err != nil {
		log.Error(err)
		output.SetExitCode(appconfig.ErrorExitCode)
		output.SetStatus(agentContracts.ResultStatusFailed)
		sessionPluginResultOutput.Output = err.Error()
		output.SetOutput(sessionPluginResultOutput)
		return
	}

	go func() {
		cancelState := cancelFlag.Wait()
		if cancelFlag.Canceled() {
			p.cancelled <- struct{}{}
			log.Debug("Cancel flag set to cancelled in session")
		}
		log.Debugf("Cancel flag set to %v in session", cancelState)
	}()

	log.Debugf("Start separate go routine to read from port connection and write to data channel")
	done := make(chan int, 1)
	go func() {
		done <- p.session.WritePump(p.dataChannel)
	}()
	log.Infof("Plugin %s started", p.name())

	select {
	case <-p.cancelled:
		log.Debug("Session cancelled. Attempting to close TCP Connection.")
		errorCode := 0
		output.SetExitCode(errorCode)
		output.SetStatus(agentContracts.ResultStatusSuccess)
		log.Info("The session was cancelled")

	case exitCode := <-done:
		if exitCode == 1 {
			output.SetExitCode(appconfig.ErrorExitCode)
			output.SetStatus(agentContracts.ResultStatusFailed)
		} else {
			output.SetExitCode(appconfig.SuccessExitCode)
			output.SetStatus(agentContracts.ResultStatusSuccess)
		}
		if cancelFlag.Canceled() {
			log.Errorf("The cancellation failed to stop the session.")
		}
	}

	log.Debug("Port session execution complete")
}

// InputStreamMessageHandler passes payload byte stream to port
func (p *PortPlugin) InputStreamMessageHandler(log log.T, streamDataMessage mgsContracts.AgentMessage) error {

	switch mgsContracts.PayloadType(streamDataMessage.PayloadType) {

	case mgsContracts.Syn:
		log.Infof("Syn payload received: %v", string(streamDataMessage.Payload))

		var synpayload mgsContracts.SynPayload
		if err := json.Unmarshal(streamDataMessage.Payload, &synpayload); err != nil {
			// not a keysplitting error, also we can't possibly have the hpointer so it wouldn't be possible to associate the error with the correct message
			return fmt.Errorf("Error occurred while parsing SynPayload json: %v", err)
		}
		log.Infof("SynPayload unmarshalled...")

		// Get nonce either rand or hpointer (if there is one)
		nonce := p.ksHelper.GetNonce()

		// Update hpointer so we have it for the error messages
		if err := p.ksHelper.UpdateHPointer(synpayload.Payload); err != nil {
			log.Info("error updating hpointer: %v", err)
		}

		// pretty legit BZECert verification
		if err := p.ksHelper.VerifyBZECert(synpayload.Payload.BZECert); err != nil {
			log.Infof("BZECert did not pass check: %v", err)
			return err
		}

		// Client Signature verification
		// if ok := p.ksHelper.VerifySignature(synpayload.Payload, synpayload.Signature, synpayload.Payload.BZECert); !ok {
		// 	kerr := p.ksHelper.BuildError("Signature Verification Failed")
		// 	return &kerr
		// }

		// Validate that TargetId == Hash(pubkey)
		if err := p.ksHelper.VerifyTargetId(synpayload.Payload.TargetId); err != nil {
			log.Infof("Invalid TargetId: %v", err)
			return err
		}

		// Tells parent Datachannel object to send SYNACK message with specified payload
		return &mgsContracts.KeysplittingError{
			Err:     errors.New("SYNACK"),
			Content: p.ksHelper.BuildSynAck(nonce, synpayload),
		}
	case mgsContracts.Data:
		log.Infof("Data payload received: %v", string(streamDataMessage.Payload))

		var datapayload mgsContracts.DataPayload
		if err := json.Unmarshal(streamDataMessage.Payload, &datapayload); err != nil {
			return fmt.Errorf("Error occurred while parsing DataPayload json: %v", err)
		}
		log.Infof("DataPayload unmarshalled...")

		// Update hpointer, needs to be done asap for error reporting purposes
		if err := p.ksHelper.UpdateHPointer(datapayload.Payload); err != nil {
			log.Info("error updating hpointer: %v", err)
		}

		// Make sure BZECert hash matches existing hash
		// In the future we should be getting a hash here that we can easily lookup in the map
		if err := p.ksHelper.CheckBZECert(datapayload.Payload.BZECert); err != nil {
			log.Infof("Invalid BZECert.  Does not match a previously recieved SYN")
			return err
		}

		// Client Signature verification
		if ok := p.ksHelper.VerifySignature(datapayload.Payload, datapayload.Signature, datapayload.Payload.BZECert); !ok {
			kerr := p.ksHelper.BuildError("Signature Verification Failed")
			return &kerr
		}

		// Validate hpointer
		if err := p.ksHelper.VerifyHPointer(datapayload.Payload.HPointer); err != nil {
			log.Infof("Expected Hpointer: %v did not equal received Hpointer %v.", p.ksHelper.ExpectedHPointer, datapayload.Payload.HPointer)
			return err
		}

		// Validate that TargetId == Hash(pubkey)
		if err := p.ksHelper.VerifyTargetId(datapayload.Payload.TargetId); err != nil {
			log.Infof("Invalid TargetId: %v", err)
			return err
		}

		// Do something with action
		switch datapayload.Payload.Action {
		case "ssh/open":
			log.Infof("Consider ssh/open done! Even though nothing will happen")
		case "ssh/close":
			log.Infof("ssh/close action not yet implemented on ssm-agent")
		default:
			log.Errorf("Attempted Keysplitting action not recognized: %v", datapayload.Payload.Action)
		}

		// Tells parent Datachannel object to send DATAACK message with specified payload
		return &mgsContracts.KeysplittingError{
			Err:     errors.New("DATAACK"),
			Content: p.ksHelper.BuildDataAck(datapayload),
		}
	default:
		if p.session == nil || !p.session.IsConnectionAvailable() {
			// This is to handle scenario when cli/console starts sending data but session has not been initialized yet
			// Since packets are rejected, cli/console will resend these packets until tcp starts successfully in separate thread
			log.Tracef("TCP connection unavailable. Reject incoming message packet")
			return mgsContracts.ErrHandlerNotReady
		} else {
			return p.session.HandleStreamMessage(streamDataMessage)
		}
	}
}

// Stop closes all opened connections to port
func (p *PortPlugin) stop() {
	p.context.Log().Debug("Closing all connections")
	if p.session != nil {
		p.session.Stop()
	}
}

// initializeParameters initializes PortPlugin with input parameters
func (p *PortPlugin) initializeParameters(config agentContracts.Configuration) (err error) {
	var portParameters PortParameters
	if err = jsonutil.Remarshal(config.Properties, &portParameters); err != nil {
		return errors.New(fmt.Sprintf("Unable to remarshal session properties. %v", err))
	}

	if portParameters.PortNumber == "" {
		return errors.New(fmt.Sprintf("Port number is empty in session properties. %v", config.Properties))
	}
	p.session, err = GetSession(p.context, portParameters, p.cancelled, p.dataChannel.GetClientVersion(), config.SessionId)

	return
}
