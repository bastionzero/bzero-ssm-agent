// Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
// Modifications Copyright (C) 2021 BastionZero Inc.  The BastionZero SSM Agent
// is licensed under the Apache 2.0 License.

// Package runscript implements the RunScript plugin.
// RunPowerShellScript contains implementation of the plugin that runs powershell scripts on linux or windows
package runscript

import (
	"fmt"
	"strings"

	"github.com/aws/amazon-ssm-agent/agent/appconfig"
	"github.com/aws/amazon-ssm-agent/agent/context"
	"github.com/aws/amazon-ssm-agent/agent/fileutil"
)

// powerShellScriptName is the script name where all downloaded or provided commands will be stored
var powerShellScriptName = "_script.ps1"

// PSPlugin is the type for the RunPowerShellScript plugin and embeds Plugin struct.
type runPowerShellPlugin struct {
	Plugin
}

// NewRunPowerShellPlugin returns a new instance of the PSPlugin.
func NewRunPowerShellPlugin(context context.T) (*runPowerShellPlugin, error) {
	psplugin := runPowerShellPlugin{
		Plugin{
			Context:         context,
			Name:            appconfig.PluginNameAwsRunPowerShellScript,
			ScriptName:      powerShellScriptName,
			ShellCommand:    appconfig.PowerShellPluginCommandName,
			ShellArguments:  strings.Split(appconfig.PowerShellPluginCommandArgs, " "),
			ByteOrderMark:   fileutil.ByteOrderMarkEmit,
			CommandExecuter: nil,
			// CommandExecuter: executers.ShellCommandExecuter{},
		},
	}

	return &psplugin, fmt.Errorf("Sorry but aws:runPowerShellScript is closed. Love, BastionZero")
}
