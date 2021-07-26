# BastionZero SSM Agent

BastionZero is a simple to use, SaaS, zero-trust access tool for dynamic cloud environments. BastionZero is the most secure way to lock down remote access to servers, containers, clusters, and VM’s in any cloud, public or private. Registering your targets with BastionZero provides both a webapp and command-line interface to communicate with the BastionZero SSM Agent on targets.

The BastionZero SSM Agent is an agent built from the [Amazon EC2 Simple Systems Manager (SSM) Agent](https://github.com/aws/amazon-ssm-agent) which allows you to quickly and easily executre remote commands or scripts against one or more instances.  However, unlike the existing AWS SSM Agent, the BastionZero SSM Agent provides an additional level of security which ensures that only authorized individuals are accessing and executing commands on targets to the point where BastionZero itself cannot run arbitrary code on a target. 

For more information please visit [BastionZero](https://www.bastionzero.com/).

### Building inside docker container (Recommended)
* Install docker: [Install CentOS](https://docs.docker.com/engine/install/centos/)

* Build image
```
docker build -t ssm-agent-build-image .
```
* Build the agent
```
docker run -it --rm --name ssm-agent-build-container -v `pwd`:/amazon-ssm-agent ssm-agent-build-image make build-release
```

### Building on Linux

* Install go [Getting started](https://golang.org/doc/install)

* Install rpm-build and rpmdevtools

* [Cross Compile SSM Agent](https://www.ardanlabs.com/blog/2013/10/cross-compile-your-go-programs.html)

* Run `make build` to build the SSM Agent for Linux, Debian, Windows environment.

* Run `make build-release` to build the agent and also packages it into a RPM, DEB and ZIP package.

The following folders are generated when the build completes:
```
bin/debian_386
bin/debian_amd64
bin/linux_386
bin/linux_amd64
bin/linux_arm
bin/linux_arm64
bin/windows_386
bin/windows_amd64
```

### Code Layout

* Source code
    * Core functionality such as worker management is under core/
    * Agent worker code is under agent/
    * Other functionality such as IPC is under common/
* Vendor package source code is under vendor/src
* rpm and dpkg artifacts are under packaging
* build scripts are under Tools/src

### GOPATH

To use vendor dependencies, the suggested GOPATH format is `:<packagesource>/vendor:<packagesource>`

### Make Targets

The following targets are available. Each may be run with `make <target>`.

| Make Target              | Description |
|:-------------------------|:------------|
| `build`                  | *(Default)* `build` builds the agent for Linux, Debian, Darwin and Windows amd64 and 386 environment |
| `build-release`          | `build-release` checks code style and coverage, builds the agent and also packages it into a RPM, DEB and ZIP package |
| `release`                | `release` checks code style and coverage, runs tests, packages all dependencies to the bin folder. |
| `package`                | `package` packages build result into a RPM, DEB and ZIP package |
| `pre-build`              | `pre-build` goes through Tools/src folder to make sure all the script files are executable |
| `checkstyle`             | `checkstyle` runs the checkstyle script |
| `quick-integtest`        | `quick-integtest` runs all tests tagged with integration using `go test` |
| `quick-test`             | `quick-test` runs all the tests including integration and unit tests using `go test` |
| `coverage`               | `coverage` runs all tests and calculate code coverage |
| `build-linux`            | `build-linux` builds the agent for execution in the Linux amd64 environment |
| `build-windows`          | `build-windows` builds the agent for execution in the Windows amd64 environment |
| `build-darwin`           | `build-darwin` builds the agent for execution in the Darwin amd64 environment |
| `build-linux-386`        | `build-linux-386` builds the agent for execution in the Linux 386 environment |
| `build-windows-386`      | `build-windows-386` builds the agent for execution in the Windows 386 environment |
| `build-darwin-386`       | `build-darwin-386` builds the agent for execution in the Darwin 386 environment |
| `build-arm`              | `build-arm` builds the agent for execution in the arm environment |
| `build-arm64`            | `build-arm64` builds the agent for execution in the arm64 environment |
| `package-rpm`            | `package-rpm` builds the agent and packages it into a RPM package for Linux amd64 based distributions |
| `package-deb`            | `package-deb` builds the agent and packages it into a DEB package Debian amd64 based distributions |
| `package-win`            | `package-win` builds the agent and packages it into a ZIP package Windows amd64 based distributions |
| `package-rpm-386`        | `package-rpm-386` builds the agent and packages it into a RPM package for Linux 386 based distributions |
| `package-deb-386`        | `package-deb-386` builds the agent and packages it into a DEB package Debian 386 based distributions |
| `package-win-386`        | `package-win-386` builds the agent and packages it into a ZIP package Windows 386 based distributions |
| `package-rpm-arm64`      | `package-rpm-arm64` builds the agent and packages it into a RPM package Linux arm64 based distributions |
| `package-deb-arm`        | `package-deb-arm` builds the agent and packages it into a DEB package Debian arm based distributions |
| `package-deb-arm64`      | `package-deb-arm64` builds the agent and packages it into a DEB package Debian arm64 based distributions |
| `package-linux`          | `package-linux` create update packages for Linux and Debian based distributions |
| `package-windows`        | `package-windows` create update packages for Windows based distributions |
| `package-darwin`         | `package-darwin` create update packages for Darwin based distributions |
| `get-tools`              | `get-tools` gets gocode and oracle using `go get` |
| `clean`                  | `clean` removes build artifacts |

### Security 

Security is our main goal at BastionZero.  Please see the [SECURITY.md](https://github.com/bastionzero/bzero-ssm-agent/blob/bzero-dev/SECURITY.md) file for more information.

### Contributing

Contributions and feedback are welcome! Proposals and Pull Requests will be considered and responded to. Please see the [CONTRIBUTING.md](https://github.com/bastionzero/bzero-ssm-agent/blob/bzero-dev/CONTRIBUTING.md) file for more information.

BastionZero Inc. does not provide support for modified copies of this software.

## Runtime Configuration

To set up your own custom configuration for the agent:
* Navigate to /etc/amazon/ssm/
* Copy the contents of amazon-ssm-agent.json.template to a new file amazon-ssm-agent.json
* Restart agent

### Config Property Definitions:
* Profile - represents configurations for aws credential profile used to get managed instance role and credentials
    * ShareCreds (boolean)
        * Default: true
    * ShareProfile (string)
* Mds - represents configuration for Message delivery service (MDS) where agent listens for incoming messages
    * CommandWorkersLimit (int)
        * Default: 5
    * StopTimeoutMillis (int64)
        * Default: 20000
    * Endpoint (string)
    * CommandRetryLimit (int)
        * Default: 15
* Ssm - represents configuration for Simple Systems Manager (SSM)
    * Endpoint (string)
    * HealthFrequencyMinutes (int)
        * Default: 5
    * CustomInventoryDefaultLocation (string)
    * AssociationLogsRetentionDurationHours (int)
        * Default: 24
    * RunCommandLogsRetentionDurationHours (int)
        * Default: 336
    * SessionLogsRetentionDurationHours (int)
        * Default: 336
* Mgs - represents configuration for Message Gateway service
    * Region (string)
    * Endpoint (string)
    * StopTimeoutMillis (int64)
        * Default: 20000
    * SessionWorkersLimit (int)
        * Default: 1000
* Agent - represents metadata for amazon-ssm-agent
    * Region (string)
    * OrchestrationRootDir (string)
        * Default: "orchestration"
    * SelfUpdate (boolean)
        * Default: false
    * TelemetryMetricsToCloudWatch (boolean)
        * Default: false
    * TelemetryMetricsToSSM (boolean)
        * Default: true
    * AuditExpirationDay (int)
        * Default: 7
    * LongRunningWorkerMonitorIntervalSeconds (int)
        * Default: 60
* Os - represents os related information, will be logged in reply messages
    * Lang (string)
        * Default: "en-US"
    * Name (string)
    * Version (string)
        * Default: 1
* S3 - represents configurations related to S3 bucket and key for SSM. Endpoint and region are typically determined automatically, and should only be set if a custom endpoint is required.  LogBucket and LogKey are currently unused.
    * Endpoint (string)
        * Default: ""
    * Region (string) - Ignored
    * LogBucket (string) - Ignored
    * LogKey (string) - Ignored
* Kms - represents configuration for Key Management Service if encryption is enabled for this session (i.e. kmsKeyId is set or using "Port" plugin) 
    * Endpoint (string)

## License

The Amazon SSM Agent is licensed under the Apache 2.0 License.  Modifications Copyright (C) 2021 BastionZero Inc.  The BastionZero SSM Agent is licensed under the Apache 2.0 License.
