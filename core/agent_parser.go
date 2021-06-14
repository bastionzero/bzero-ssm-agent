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
// Parser contains logic for commandline handling flags
package main

import (
	ed "crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/aws/amazon-ssm-agent/agent/appconfig"
	bzeroreg "github.com/aws/amazon-ssm-agent/agent/bzero/registration"
	logger "github.com/aws/amazon-ssm-agent/agent/log"
	"github.com/aws/amazon-ssm-agent/agent/managedInstances/fingerprint"
	"github.com/aws/amazon-ssm-agent/agent/managedInstances/registration"
	vault "github.com/aws/amazon-ssm-agent/agent/managedInstances/vault/fsvault"
	"github.com/aws/amazon-ssm-agent/agent/ssm/anonauth"
	"github.com/aws/amazon-ssm-agent/agent/version"
)

// parseFlags displays flags and handles them
func parseFlags() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flag.Usage = flagUsage

	// managed instance registration
	flag.BoolVar(&register, registerFlag, false, "")
	flag.StringVar(&activationCode, activationCodeFlag, "", "")
	flag.StringVar(&activationID, activationIDFlag, "", "")
	flag.StringVar(&region, regionFlag, "", "")
	flag.BoolVar(&agentVersionFlag, versionFlag, false, "")

	// clear registration
	flag.BoolVar(&clear, "clear", false, "")

	// fingerprint similarity threshold
	flag.BoolVar(&fpFlag, fingerprintFlag, false, "")
	flag.IntVar(&similarityThreshold, similarityThresholdFlag, 40, "")

	// force flag
	flag.BoolVar(&force, "y", false, "")

	// Show bzeroInfo flag
	flag.BoolVar(&bzeroInfo, bzeroInfoFlag, false, "")

	// Bzero Registration flag
	flag.StringVar(&bzero, bzeroFlag, "", "")

	// BZero Org flags
	flag.StringVar(&orgID, orgIDFlag, "", "")
	flag.StringVar(&orgProvider, orgProviderFlag, "", "")

	flag.Parse()
}

func handleBZeroInfo() {
	if flag.NFlag() == 1 {
		if bzeroInfo {
			printBZeroInfo("Version: " + version.Version)
			printBZeroPubKey()
			os.Exit(0)
		}
	}
}

// This function is without logger and will not print extra statements
func printBZeroPubKey() {
	bzeroConfig := map[string]string{}

	config, err := vault.Retrieve(bzeroreg.BZeroConfigStorage)
	if err != nil {
		fmt.Printf("Error Retrieving BZero Config: %v", err)
		os.Exit(bzeroreg.BZeroRegErrorExitCode)
	} else if config == nil {
		fmt.Printf("BZero Config File is Empty!")
		os.Exit(bzeroreg.BZeroRegErrorExitCode)
	}

	// Unmarshal the retrieved data
	if err := json.Unmarshal([]byte(config), &bzeroConfig); err != nil {
		fmt.Printf("Error Retrieving BZero Config: %v", err)
		os.Exit(1)
	}

	printBZeroInfo(bzeroConfig["PublicKey"])
}

func printBZeroInfo(info string) {
	fmt.Printf("[BZeroAgentInfo]%s\n", info)
}

func bzeroInit(log logger.T) (exitCode int) {
	// BZero Init function to:
	//  * Verify orgProvider, if custom
	//  * Generate Pub/Priv keypair
	//  * Store keys along with passed orgID

	// Generate public private key pair along ed25519 curve
	publicKey, privateKey, err := ed.GenerateKey(nil)

	// Catch any errors that might have been generated
	if err != nil {
		log.Errorf("BZero Key Generation Failed: %v", err)
		return bzeroreg.BZeroRegErrorExitCode
	}

	// Convert our keys to hex format before storing it
	pubkeyString := base64.StdEncoding.EncodeToString([]byte(publicKey))
	privkeyString := base64.StdEncoding.EncodeToString([]byte(privateKey))

	keys := map[string]string{
		"PublicKey":            pubkeyString,
		"PrivateKey":           privkeyString,
		"OrganizationID":       orgID,
		"OrganizationProvider": orgProvider,
	}
	data, err := json.Marshal(keys)
	if err != nil {
		log.Errorf("Marshalling BZero Keys Failed: %v", err)
		return bzeroreg.BZeroRegErrorExitCode
	}

	if err = vault.Store(bzeroreg.BZeroConfigStorage, data); err != nil {
		log.Errorf("Storing Bzero Config Failed: %v", err)
		return bzeroreg.BZeroRegErrorExitCode
	}

	log.Info("Successfully Created and Stored BZero Config!")
	return 0
}

func processBZeroRegistration(log logger.T) (exitCode int) {
	var regInfo bzeroreg.BZeroRegInfo

	// We're going to unmarshal and then marshal the data because we want to make sure we
	// control the variable names and only store the things that we'll know what to do with.
	// Also, this way we can catch if the data in malformed or was incorrectly generated asap
	if err := json.Unmarshal([]byte(bzero), &regInfo); err != nil {
		log.Errorf("Malformed BZero Registration Info, Could Not Unmarshal Data")
		return bzeroreg.BZeroRegErrorExitCode
	}

	// check if all required fields present
	if bzeroreg.MissingBZeroRegFields(regInfo) {
		return bzeroreg.BZeroRegErrorExitCode
	}

	data, _ := json.Marshal(regInfo)

	if err := vault.Store(bzeroreg.BZeroRegStorage, data); err != nil {
		log.Errorf("BZero Storing of Registration Information Failed: %v", err)
		return bzeroreg.BZeroRegErrorExitCode
	}

	log.Infof("Successfully Stored BZero Registration Data")

	// Try to register just in case it works and then the agent can start more smoothely on the first try
	// We don't care if there's an error here, because it's a bonus action and not core to the registration
	// process
	checkAndRegister(log, false)

	return 0
}

// handles registration and fingerprint flags
func handleRegistrationAndFingerprintFlags(log logger.T) {
	if flag.NFlag() > 0 {
		exitCode := 1
		if register {
			if bzero != "" {
				exitCode = processBZeroRegistration(log)
			} else {
				exitCode = bzeroInit(log)
				exitCode = processRegistration(log)
			}
		} else if fpFlag {
			exitCode = processFingerprint(log)
		} else {
			flagUsage()
		}
		log.Flush()
		log.Close()
		os.Exit(exitCode)
	}
}

// handles agent version flag.
// This function is without logger and will not print extra statements
func handleAgentVersionFlag() {
	if flag.NFlag() == 1 {
		if agentVersionFlag {
			fmt.Println("SSM Agent version: " + version.Version)
			os.Exit(0)
		}
	}
}

// flagUsage displays a command-line friendly usage message
func flagUsage() {
	fmt.Fprintln(os.Stderr, "\n\nCommand-line Usage:")
	fmt.Fprintln(os.Stderr, "\t-register\tregister managed instance")
	fmt.Fprintln(os.Stderr, "\t\t-id\tSSM activation ID")
	fmt.Fprintln(os.Stderr, "\t\t-code\tSSM activation code")
	fmt.Fprintln(os.Stderr, "\t\t-region\tSSM region")
	fmt.Fprintln(os.Stderr, "\n\t\t-clear\tClears the previously saved SSM registration")
	fmt.Fprintln(os.Stderr, "\t-fingerprint\tWhether to update the machine fingerprint similarity threshold\t(OPTIONAL)")
	fmt.Fprintln(os.Stderr, "\t\t-similarityThreshold\tThe new required percentage of matching hardware values\t(OPTIONAL)")
	fmt.Fprintln(os.Stderr, "\n\t-y\tAnswer yes for all questions")
}

// processRegistration handles flags related to the registration category
func processRegistration(log logger.T) (exitCode int) {
	if activationCode == "" || activationID == "" || region == "" {
		// clear registration
		if clear {
			return clearRegistration(log)
		}
		flagUsage()
		return 1
	}

	// check if previously registered
	if !force && registration.InstanceID() != "" {
		confirmation, err := askForConfirmation()
		if err != nil {
			log.Errorf("Registration failed due to %v", err)
			return 1
		}

		if !confirmation {
			log.Info("Registration canceled by user")
			return 1
		}
	}

	managedInstanceID, err := registerManagedInstance(log)
	if err != nil {
		log.Errorf("Registration failed due to %v", err)
		return 1
	}

	log.Infof("Successfully registered the instance with AWS SSM using Managed instance-id: %s", managedInstanceID)
	return 0
}

// processFingerprint handles flags related to the fingerprint category
func processFingerprint(log logger.T) (exitCode int) {
	if err := fingerprint.SetSimilarityThreshold(similarityThreshold); err != nil {
		log.Errorf("Error setting the SimilarityThreshold. %v", err)
		return 1
	}
	log.Infof("Fingerprint SimilarityThreshold set to %v", similarityThreshold)
	return 0
}

// registerManagedInstance checks for activation credentials and performs managed instance registration when present
func registerManagedInstance(log logger.T) (managedInstanceID string, err error) {
	// try to activate the instance with the activation credentials
	publicKey, privateKey, keyType, err := registration.GenerateKeyPair()
	if err != nil {
		return managedInstanceID, fmt.Errorf("error generating signing keys. %v", err)
	}

	// checking write access before registering
	err = registration.UpdateServerInfo("", "", privateKey, keyType)
	if err != nil {
		return managedInstanceID,
			fmt.Errorf("Unable to save registration information. %v\nTry running as sudo/administrator.", err)
	}

	// generate fingerprint
	fingerprint, err := registration.Fingerprint()
	if err != nil {
		return managedInstanceID, fmt.Errorf("error generating instance fingerprint. %v", err)
	}

	service := anonauth.NewAnonymousService(log, region)
	managedInstanceID, err = service.RegisterManagedInstance(
		activationCode,
		activationID,
		publicKey,
		keyType,
		fingerprint,
	)
	if err != nil {
		return managedInstanceID, fmt.Errorf("error registering the instance with AWS SSM. %v", err)
	}

	err = registration.UpdateServerInfo(managedInstanceID, region, privateKey, keyType)
	if err != nil {
		return managedInstanceID, fmt.Errorf("error persisting the instance registration information. %v", err)
	}

	// saving registration information to the registration file
	reg := map[string]string{
		"ManagedInstanceID": managedInstanceID,
		"Region":            region,
	}

	var regData []byte
	if regData, err = json.Marshal(reg); err != nil {
		return "", fmt.Errorf("Failed to marshal registration info. %v", err)
	}

	if err = ioutil.WriteFile(registrationFile, regData, appconfig.ReadWriteAccess); err != nil {
		return "", fmt.Errorf("Failed to write registration info to file. %v", err)
	}

	return managedInstanceID, nil
}

// clearRegistration clears any existing registration data
func clearRegistration(log logger.T) (exitCode int) {
	err := registration.UpdateServerInfo("", "", "", "")
	if err == nil {
		log.Info("Registration information has been removed from the instance.")
		return 0
	}
	log.Errorf("error clearing the instance registration information. %v\nTry running as sudo/administrator.", err)
	return 1
}

// askForConfirmation will ask user for confirmation if they want to proceed.
func askForConfirmation() (result bool, err error) {
	var response string
	fmt.Print("\nInstance already registered. Would you like to override existing with new registration information? [Yes/No]: ")
	_, err = fmt.Scanln(&response)
	if err != nil {
		return false, err
	}

	if len(response) > 0 {
		firstChar := strings.ToLower(string(response[0]))
		if firstChar == "y" {
			return true, nil
		}
		if firstChar == "n" {
			return false, nil
		}
	}
	return false, fmt.Errorf("Invalid response received.")
}
