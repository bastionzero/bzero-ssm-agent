// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

// Package main represents the entry point of the agent.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"

	"github.com/aws/amazon-ssm-agent/agent/appconfig"
	bzeroreg "github.com/aws/amazon-ssm-agent/agent/bzero/registration"
	"github.com/aws/amazon-ssm-agent/agent/log"
	logger "github.com/aws/amazon-ssm-agent/agent/log"
	"github.com/aws/amazon-ssm-agent/agent/managedInstances/registration"
	vault "github.com/aws/amazon-ssm-agent/agent/managedInstances/vault/fsvault"
	"github.com/aws/amazon-ssm-agent/core/app"
	"github.com/aws/amazon-ssm-agent/core/app/bootstrap"
	"github.com/aws/amazon-ssm-agent/core/ipc/messagebus"
	"github.com/aws/amazon-ssm-agent/core/workerprovider/longrunningprovider/datastore/filesystem"
)

const (
	activationCodeFlag      = "code"
	activationIDFlag        = "id"
	regionFlag              = "region"
	registerFlag            = "register"
	versionFlag             = "version"
	fingerprintFlag         = "fingerprint"
	similarityThresholdFlag = "similarityThreshold"
	bzeroInfoFlag           = "bzeroInfo"
	bzeroFlag               = "bzero"
)

var (
	activationCode, activationID, region             string
	orgID, orgProvider, bzero                        string // bzero args
	register, clear, force, fpFlag, agentVersionFlag bool
	bzeroInfo                                        bool // bzero args
	similarityThreshold                              int
	registrationFile                                 = filepath.Join(appconfig.DefaultDataStorePath, "registration")
)

func start(log logger.T) (app.CoreAgent, logger.T, error) {
	log.WriteEvent(logger.AgentTelemetryMessage, "", logger.AmazonAgentStartEvent)

	if err := checkAndRegister(log, true); err != nil {
		log.Errorf(err.Error())
		log.Infof("Error during BZero Registration; Exiting")
		return nil, log, err
	}

	bs := bootstrap.NewBootstrap(log, filesystem.NewFileSystem())
	context, err := bs.Init()
	if err != nil {
		return nil, log, err
	}

	context = context.With("[bzero-ssm-agent]")
	message := messagebus.NewMessageBus(context)
	if err := message.Start(); err != nil {
		return nil, log, fmt.Errorf("Failed to start message bus, %s", err)
	}

	ssmAgentCore := app.NewSSMCoreAgent(context, message)
	ssmAgentCore.Start()

	return ssmAgentCore, context.Log(), nil
}

func checkAndRegister(log log.T, retry bool) error {
	// Check if there is an activation code to see if we've already registered
	// force variable is only relevant if we're calling this from command line
	// it allows us to overwrite an existing registration.
	if registration.InstanceID() == "" || force {
		if !hasRegistrationInfo() {
			return fmt.Errorf("This Agent does not have the required BZero registration information in order to register.")
		}

		log.Infof("Agent is not Registered with BZero.  Attempting to register now...")
		if resp, err := bzeroreg.Register(log, retry); err != nil {
			return err
		} else {
			log.Infof("Agent is now Registered with BZero.  Activating Agent...")
			// Try to activate agent (which includes the standard aws registration + bzero config setup)
			if err := activateAgent(resp, log); err != nil {
				return fmt.Errorf("Error Activating Agent: %v", err)
			} else {
				log.Infof("Sucessfully Activated Agent")
				return nil
			}
		}
	} else {
		log.Infof("Agent is registered with BZero.")
		return nil
	}
}

// Check for registration information
func hasRegistrationInfo() bool {
	if awsRegFile, err := vault.Retrieve(bzeroreg.BZeroRegStorage); err != nil || awsRegFile == nil {
		return false
	} else {
		return true
	}
}

// Process registration once details are retrieved from bzero
func activateAgent(resp bzeroreg.BZeroRegResponse, log logger.T) error {
	activationCode = resp.ActivationCode
	activationID = resp.ActivationId
	region = resp.ActivationRegion

	orgID = resp.OrgID
	orgProvider = resp.OrgProvider

	if registration.InstanceID() != "" {
		clearRegistration(log)
	}

	if code := processRegistration(log); code != 0 {
		return fmt.Errorf("Error Processing Standard Registration")
	}

	if code := bzeroInit(log); code != 0 {
		return fmt.Errorf("Error while Initializing Bzero Variables")
	}

	if err := vault.Remove(bzeroreg.BZeroRegStorage); err != nil {
		return fmt.Errorf("Error Deleting BZero Registration Data: %v", err)
	}

	return nil
}

func blockUntilSignaled(log logger.T) {
	// Below channel will handle all machine initiated shutdown/reboot requests.

	// Set up channel on which to receive signal notifications.
	// We must use a buffered channel or risk missing the signal
	// if we're not ready to receive when the signal is sent.
	c := make(chan os.Signal, 1)

	// Listening for OS signals is a blocking call.
	// Only listen to signals that require us to exit.
	// Otherwise we will continue execution and exit the program.
	signal.Notify(c, os.Interrupt, os.Kill, syscall.SIGTERM)

	s := <-c
	log.Info("Got signal:", s, " value:", s.Signal)
}

// Run as a single process. Used by Unix systems and when running agent from console.
func run(log logger.T) {
	defer func() {
		// recover in case the agent panics
		// this should handle some kind of seg fault errors.
		if msg := recover(); msg != nil {
			log.Errorf("Core Agent crashed with message %v!", msg)
			log.Errorf("%s: %s", msg, debug.Stack())
		}
	}()

	// run ssm agent
	coreAgent, contextLog, err := start(log)
	if err != nil {
		contextLog.Errorf("Error occurred when starting bzero-ssm-agent: %v", err)
		return
	}
	blockUntilSignaled(contextLog)
	coreAgent.Stop()
}
