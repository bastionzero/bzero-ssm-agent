// Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

// +build freebsd linux netbsd openbsd

package log

import (
	"fmt"
	"io/ioutil"

	"github.com/aws/amazon-ssm-agent/agent/appconfig"
)

const (
	DefaultLogDir = "/var/log/bzero/ssm"
)

// DefaultSeelogConfigFilePath specifies the default seelog location
// The underlying logger is based of https://github.com/cihub/seelog
// See Seelog documentation to customize the logger
var DefaultSeelogConfigFilePath = appconfig.SeelogFilePath

// getLogConfigBytes reads and returns the seelog configs from the config file path if present
// otherwise returns the seelog default configurations
// Linux uses seelog.xml file as configuration by default.
func getLogConfigBytes() (logConfigBytes []byte) {
	var err error
	if logConfigBytes, err = ioutil.ReadFile(DefaultSeelogConfigFilePath); err != nil {
		fmt.Println("Error occurred fetching the seelog config file path: ", err)
		logConfigBytes = DefaultConfig()
	}
	return
}
