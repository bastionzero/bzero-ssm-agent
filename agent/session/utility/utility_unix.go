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

// +build darwin freebsd linux netbsd openbsd

// utility package implements all the shared methods between clients.
package utility

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/aws/amazon-ssm-agent/agent/appconfig"
	"github.com/aws/amazon-ssm-agent/agent/context"
	"github.com/aws/amazon-ssm-agent/agent/fileutil"
	"github.com/aws/amazon-ssm-agent/agent/log"
	"github.com/aws/amazon-ssm-agent/agent/session/utility/model"
)

var ShellPluginCommandName = "sh"
var ShellPluginBashCommandName = "/bin/bash"
var ShellPluginCommandArgs = []string{"-c"}

const (
	sudoersFile     = "/etc/sudoers.d/ssm-agent-users"
	sudoersFileMode = 0440
	fs_ioc_getflags = uintptr(0x80086601)
	fs_ioc_setflags = uintptr(0x40086602)
	FS_APPEND_FL    = 0x00000020 /* writes to file may only append */
	FS_RESET_FL     = 0x00000000 /* reset file property */
)

// ResetPasswordIfDefaultUserExists resets default RunAs user password if user exists
func (u *SessionUtil) ResetPasswordIfDefaultUserExists(context context.T) (err error) {
	// Do nothing here as no password is required for unix platform local user
	return nil
}

// DoesUserExist checks if given user already exists
func (u *SessionUtil) DoesUserExist(username string) (bool, error) {
	shellCmdArgs := append(ShellPluginCommandArgs, fmt.Sprintf("id %s", username))
	cmd := exec.Command(ShellPluginCommandName, shellCmdArgs...)
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// The program has exited with an exit code != 0
			return false, fmt.Errorf("encountered an error while checking for %s: %v", appconfig.DefaultRunAsUserName, exitErr.Error())
		}
		return false, nil
	}
	return true, nil
}

// createLocalAdminUser creates a local OS user on the instance with admin permissions. The password will alway be empty
func (u *SessionUtil) CreateLocalAdminUser(log log.T) (newPassword string, err error) {

	userExists, _ := u.DoesUserExist(appconfig.DefaultRunAsUserName)

	if userExists {
		log.Infof("%s already exists.", appconfig.DefaultRunAsUserName)
	} else {
		if err = u.createLocalUser(log); err != nil {
			return
		}
		// only create sudoers file when user does not exist
		err = u.createSudoersFileIfNotPresent(log)
	}

	return
}

// createLocalUser creates an OS local user.
func (u *SessionUtil) createLocalUser(log log.T) error {

	commandArgs := append(ShellPluginCommandArgs, fmt.Sprintf(model.AddUserCommand, appconfig.DefaultRunAsUserName))
	cmd := exec.Command(ShellPluginCommandName, commandArgs...)
	if err := cmd.Run(); err != nil {
		log.Errorf("Failed to create %s: %v", appconfig.DefaultRunAsUserName, err)
		return err
	}
	log.Infof("Successfully created %s", appconfig.DefaultRunAsUserName)
	return nil
}

// createSudoersFileIfNotPresent will create the sudoers file if not present.
func (u *SessionUtil) createSudoersFileIfNotPresent(log log.T) error {

	// Return if the file exists
	if _, err := os.Stat(sudoersFile); err == nil {
		log.Infof("File %s already exists", sudoersFile)
		u.changeModeOfSudoersFile(log)
		return err
	}

	// Create a sudoers file for ssm-user
	file, err := os.Create(sudoersFile)
	if err != nil {
		log.Errorf("Failed to add %s to sudoers file: %v", appconfig.DefaultRunAsUserName, err)
		return err
	}
	defer file.Close()

	file.WriteString(fmt.Sprintf("# User rules for %s\n", appconfig.DefaultRunAsUserName))
	file.WriteString(fmt.Sprintf("%s ALL=(ALL) NOPASSWD:ALL\n", appconfig.DefaultRunAsUserName))
	log.Infof("Successfully created file %s", sudoersFile)
	u.changeModeOfSudoersFile(log)
	return nil
}

// changeModeOfSudoersFile will change the sudoersFile mode to 0440 (read only).
// This file is created with mode 0666 using os.Create() so needs to be updated to read only with chmod.
func (u *SessionUtil) changeModeOfSudoersFile(log log.T) error {
	fileMode := os.FileMode(sudoersFileMode)
	if err := os.Chmod(sudoersFile, fileMode); err != nil {
		log.Errorf("Failed to change mode of %s to %d: %v", sudoersFile, sudoersFileMode, err)
		return err
	}
	log.Infof("Successfully changed mode of %s to %d", sudoersFile, sudoersFileMode)
	return nil
}

func (u *SessionUtil) DisableLocalUser(log log.T) (err error) {
	// Do nothing here as no password is required for unix platform local user, so that no need to disable user.
	return nil
}

// NewListener starts a new socket listener on the address.
func NewListener(log log.T, address string) (net.Listener, error) {
	return net.Listen("unix", address)
}

// ioctl is used for making system calls to manipulate file attributes
func ioctl(f *os.File, request uintptr, attrp *int32) error {
	argp := uintptr(unsafe.Pointer(attrp))
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), request, argp)
	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}

	return nil
}

// SetAttr sets the attributes of a file on a linux filesystem to the given value
func (u *SessionUtil) SetAttr(f *os.File, attr int32) error {
	return ioctl(f, fs_ioc_setflags, &attr)
}

// GetAttr retrieves the attributes of a file on a linux filesystem
func (u *SessionUtil) GetAttr(f *os.File) (int32, error) {
	attr := int32(-1)
	err := ioctl(f, fs_ioc_getflags, &attr)
	return attr, err
}

// DeleteIpcTempFile resets file properties of ipcTempFile and tries deletion
func (u *SessionUtil) DeleteIpcTempFile(sessionOrchestrationPath string) (bool, error) {
	ipcTempFilePath := filepath.Join(sessionOrchestrationPath, appconfig.PluginNameStandardStream, "ipcTempFile.log")

	// check if ipcTempFile exists
	if _, err := os.Stat(ipcTempFilePath); err != nil {
		return false, fmt.Errorf("ipcTempFile does not exist, %v", err)
	}

	// open ipcTempFile
	ipcFile, err := os.Open(ipcTempFilePath)
	if err != nil {
		return false, fmt.Errorf("failed to open ipcTempFile %s, %v", ipcTempFilePath, err)
	}
	defer ipcFile.Close()

	// reset file attributes
	if err := u.SetAttr(ipcFile, FS_RESET_FL); err != nil {
		return false, fmt.Errorf("unable to reset file properties for %s, %v", ipcTempFilePath, err)
	}

	// delete the directory
	if err := fileutil.DeleteDirectory(sessionOrchestrationPath); err != nil {
		return false, err
	}

	return true, nil
}

// Appends an authorized key entry to the authorized_keys file within username's .ssh directory
func (u *SessionUtil) AddToAuthorizedKeyFile(username string, authorizedKey string) (bool, error) {
	// make a .ssh directory for the user if it doesnt exist and then append the authorizedKey string to the authorized_keys file within the .ssh directory
	authorizedKeyFile := fmt.Sprintf("~%s/.ssh/authorized_keys", username)
	sshFolder := fmt.Sprintf("~%s/.ssh", username)
	createSshDirectory := fmt.Sprintf("mkdir -p %s", sshFolder)
	shellCmdArgsCreateSshDirectory := append(ShellPluginCommandArgs, createSshDirectory)
	cmdCreateSshDirectory := exec.Command(ShellPluginBashCommandName, shellCmdArgsCreateSshDirectory...)
	if err := cmdCreateSshDirectory.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// The program has exited with an exit code != 0
			return false, fmt.Errorf("error executing %s %v", cmdCreateSshDirectory.Args, exitErr.Error())
		}
		return false, nil
	}

	appendKeyCmd := fmt.Sprintf("echo '%s' >> %s", authorizedKey, authorizedKeyFile)
	shellCmdArgsAppendKey := append(ShellPluginCommandArgs, lockFolderAndRunCommand(authorizedKeyFile, appendKeyCmd))
	cmdAppendKey := exec.Command(ShellPluginBashCommandName, shellCmdArgsAppendKey...)
	if err := cmdAppendKey.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// The program has exited with an exit code != 0
			return false, fmt.Errorf("error executing %s %v", cmdAppendKey.Args, exitErr.Error())
		}
		return false, nil
	}
	return true, nil
}

// Removes an authorized key entry from authorized_keys file within username's .ssh directory
func (u *SessionUtil) RemoveFromAuthorizedKeyFile(username string, authorizedKey string) (bool, error) {
	// match the entire contents of the authorized_keys file except for this specific authorizedKey entry using grep -v (inverse match)
	// save the grep output to a temporary .authorized_keys file and then use this to overwrite the authorized_keys file
	// grep will return error code 1 if it produces an empty match this is expected if there is only a single key in the authorized_keys file
	// so ignore error code for this command using ';' instead of '&&' to handle this edge case
	sshKeyFolder := fmt.Sprintf("~%s/.ssh", username)
	removeKeyCmd := fmt.Sprintf("cd ~%s/.ssh && grep -v -F '%s' authorized_keys > .authorized_keys; mv .authorized_keys authorized_keys", username, authorizedKey)
	shellCmdArgs := append(ShellPluginCommandArgs, lockFolderAndRunCommand(sshKeyFolder, removeKeyCmd))
	cmd := exec.Command(ShellPluginBashCommandName, shellCmdArgs...)
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// The program has exited with an exit code != 0
			return false, fmt.Errorf("error executing %s %v", cmd.Args, exitErr.Error())
		}
		return false, nil
	}
	return true, nil
}

// Use flock to wait for exclusive lock on fileToLock for up to 10 seconds (or exit) and then run a command
func lockFolderAndRunCommand(folderToLock string, commandToRun string) string {
	return fmt.Sprintf("flock -x -w 10 %s -c \"%s\"", folderToLock, commandToRun)
}
