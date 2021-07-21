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

// This code has been modified from the code covered by the Apache License 2.0.
// Modifications Copyright (C) 2021 BastionZero Inc.

// Package interactivecommands implements session shell plugin with interactive commands.
package interactivecommands

import (
	"fmt"
	"testing"

	"github.com/aws/amazon-ssm-agent/agent/appconfig"
	"github.com/aws/amazon-ssm-agent/agent/context"
	"github.com/aws/amazon-ssm-agent/agent/contracts"
	"github.com/aws/amazon-ssm-agent/agent/framework/processor/executer/iohandler"
	iohandlermocks "github.com/aws/amazon-ssm-agent/agent/framework/processor/executer/iohandler/mock"
	ksMock "github.com/aws/amazon-ssm-agent/agent/keysplitting/mocks"
	"github.com/aws/amazon-ssm-agent/agent/log"
	mgsContracts "github.com/aws/amazon-ssm-agent/agent/session/contracts"
	dataChannelMock "github.com/aws/amazon-ssm-agent/agent/session/datachannel/mocks"
	"github.com/aws/amazon-ssm-agent/agent/session/shell"
	"github.com/aws/amazon-ssm-agent/agent/task"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type InteractiveCommandsTestSuite struct {
	suite.Suite
	mockContext            *context.Mock
	mockLog                log.T
	mockCancelFlag         *task.MockCancelFlag
	mockDataChannel        *dataChannelMock.IDataChannel
	mockIohandler          *iohandlermocks.MockIOHandler
	mockKeySplittingHelper *ksMock.IKeysplittingHelper
	plugin                 *InteractiveCommandsPlugin
	shellProps             interface{}
}

func (suite *InteractiveCommandsTestSuite) SetupTest() {
	mockContext := context.NewMockDefault()
	mockCancelFlag := &task.MockCancelFlag{}
	mockDataChannel := &dataChannelMock.IDataChannel{}
	mockKeySplittingHelper := &ksMock.IKeysplittingHelper{}
	mockIohandler := new(iohandlermocks.MockIOHandler)
	mockLog := log.NewMockLog()

	shellProps := mgsContracts.ShellProperties{
		Linux: mgsContracts.ShellConfig{
			Commands:      "ls",
			RunAsElevated: true,
		},
		Windows: mgsContracts.ShellConfig{
			Commands:      "date",
			RunAsElevated: true,
		},
		MacOS: mgsContracts.ShellConfig{
			Commands:      "ls",
			RunAsElevated: true,
		},
	}

	suite.mockContext = mockContext
	suite.mockLog = mockLog
	suite.mockCancelFlag = mockCancelFlag
	suite.mockDataChannel = mockDataChannel
	suite.mockKeySplittingHelper = mockKeySplittingHelper
	suite.mockIohandler = mockIohandler
	suite.plugin = &InteractiveCommandsPlugin{
		context: suite.mockContext,
	}
	suite.shellProps = shellProps
}

//Execute the test suite
func TestInteractiveCommandsTestSuite(t *testing.T) {
	suite.Run(t, new(InteractiveCommandsTestSuite))
}

// Testing Name
func (suite *InteractiveCommandsTestSuite) TestName() {
	rst := suite.plugin.name()
	assert.Equal(suite.T(), rst, appconfig.PluginNameInteractiveCommands)
}

// Testing GetPluginParameters
func (suite *InteractiveCommandsTestSuite) TestGetPluginParameters() {
	assert.Equal(suite.T(), suite.plugin.GetPluginParameters(map[string]interface{}{"key": "value"}), nil)
}

// Testing Execute when cancel flag is shut down.
func (suite *InteractiveCommandsTestSuite) TestExecuteWhenCancelFlagIsShutDown() {
	suite.mockCancelFlag.On("ShutDown").Return(true)
	suite.mockIohandler.On("MarkAsShutdown").Return(nil)
	suite.plugin.shell, _ = shell.NewPlugin(suite.mockContext, suite.plugin.name())

	suite.plugin.Execute(
		contracts.Configuration{Properties: suite.shellProps},
		suite.mockCancelFlag,
		suite.mockIohandler,
		suite.mockDataChannel)

	suite.mockCancelFlag.AssertExpectations(suite.T())
	suite.mockIohandler.AssertExpectations(suite.T())
}

// Testing Execute when cancel flag is cancelled.
func (suite *InteractiveCommandsTestSuite) TestExecuteWhenCancelFlagIsCancelled() {
	suite.mockCancelFlag.On("Canceled").Return(true)
	suite.mockCancelFlag.On("ShutDown").Return(false)
	suite.mockIohandler.On("MarkAsCancelled").Return(nil)
	suite.plugin.shell, _ = shell.NewPlugin(suite.mockContext, suite.plugin.name())

	suite.plugin.Execute(
		contracts.Configuration{Properties: suite.shellProps},
		suite.mockCancelFlag,
		suite.mockIohandler,
		suite.mockDataChannel)

	suite.mockCancelFlag.AssertExpectations(suite.T())
	suite.mockIohandler.AssertExpectations(suite.T())
}

// Testing Execute happy case when the exit code is 0.
func (suite *InteractiveCommandsTestSuite) TestExecute() {
	newIOHandler := iohandler.NewDefaultIOHandler(suite.mockContext, contracts.IOConfiguration{})
	mockShellPlugin := new(shell.IShellPluginMock)
	mockShellPlugin.On("Execute", mock.Anything, suite.mockCancelFlag, newIOHandler, suite.mockDataChannel, suite.shellProps).Return()
	suite.plugin.shell = mockShellPlugin

	suite.plugin.Execute(
		contracts.Configuration{Properties: suite.shellProps},
		suite.mockCancelFlag,
		newIOHandler,
		suite.mockDataChannel)

	mockShellPlugin.AssertExpectations(suite.T())
	assert.Equal(suite.T(), 0, newIOHandler.GetExitCode())
}

// Testing Execute without properties section in the input.
func (suite *InteractiveCommandsTestSuite) TestExecuteWithoutCommands() {
	suite.mockIohandler.On("SetExitCode", 1).Return(nil)
	suite.mockIohandler.On("SetStatus", contracts.ResultStatusFailed).Return()

	sessionPluginResultOutput := mgsContracts.SessionPluginResultOutput{}
	sessionPluginResultOutput.Output = fmt.Sprintf("Commands cannot be empty for session type %s", suite.plugin.name())
	suite.mockIohandler.On("SetOutput", sessionPluginResultOutput).Return()

	suite.plugin.Execute(
		contracts.Configuration{},
		suite.mockCancelFlag,
		suite.mockIohandler,
		suite.mockDataChannel)

	suite.mockIohandler.AssertExpectations(suite.T())
}

// Testing InputStreamMessageHandler base case.
func (suite *InteractiveCommandsTestSuite) TestInputStreamMessageHandler() {
	mockShellPlugin := new(shell.IShellPluginMock)
	suite.plugin.shell = mockShellPlugin
	suite.mockKeySplittingHelper.On("BuildError", mock.Anything, mock.Anything).Return(nil)
	suite.plugin.ksHelper = suite.mockKeySplittingHelper

	err := suite.plugin.InputStreamMessageHandler(suite.mockLog, mgsContracts.AgentMessage{})

	mockShellPlugin.AssertExpectations(suite.T())
	assert.Nil(suite.T(), err)
}
