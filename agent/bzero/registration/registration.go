package registration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cenkalti/backoff"

	logger "github.com/aws/amazon-ssm-agent/agent/log"
)

const (
	BZeroConfigStorage    = "BZeroConfig"
	BZeroRegErrorExitCode = 123

	registrationEndpoint = "api/v1/ssm/register"
	prodServiceUrl       = "https://cloud.bastionzero.com/" // default
)

// This is the data sent to the Reg API
type BZeroRegRequest struct {
	RegSecret  string `json:"registrationSecret"`
	TargetName string `json:"instanceName"`
	EnvId      string `json:"environmentId"`
	EnvName    string `json:"environmentName"`
}

// For capturing response from registration API
type BZeroRegResponse struct {
	ActivationId     string `json:"activationId"`
	ActivationCode   string `json:"activationCode"`
	ActivationRegion string `json:"activationRegion"`
	SSMTargetId      string `json:"ssmTargetId"`
	OrgID            string `json:"externalOrganizationId"`
	OrgProvider      string `json:"externalOrganizationProvider"`
}

// Attempts to register as many times as is acceptable
func Register(log logger.T, apiKey string, envName string, envId string, targetName string, serviceUrl string) (BZeroRegResponse, error) {
	var response BZeroRegResponse

	// default target name to target hostname, if not provided
	if targetName == "" {
		targetName, _ = os.Hostname()
	}

	// Package data which becomes Post request body
	var regInfo = BZeroRegRequest{
		RegSecret:  apiKey,
		TargetName: targetName,
		EnvId:      envId,
		EnvName:    envName,
	}

	// Build Registration Endpoint
	regEndpoint := prodServiceUrl + registrationEndpoint
	if serviceUrl != "" {
		regEndpoint = fmt.Sprintf("%s/%s", strings.TrimRight(serviceUrl, "/"), registrationEndpoint)
	}

	// Register with BastionZero
	resp, err := post(log, regInfo, regEndpoint)
	if err != nil {
		return response, err
	}

	// Read body
	defer resp.Body.Close()
	respBytes, err := ioutil.ReadAll(resp.Body)

	// Unmarshal response into struct
	if err := json.Unmarshal(respBytes, &response); err != nil {
		return response, fmt.Errorf("error unmarshalling registration API response: %v", string(respBytes))

		// Check all required response fields are present
	} else if fields, ok := missingResponseFields(response); !ok {
		return response, fmt.Errorf("missing fields in registration API response: %v", fields)
	}

	return response, nil
}

func post(log logger.T, regInfo BZeroRegRequest, regUrl string) (*http.Response, error) {
	// Default params
	// Ref: https://github.com/cenkalti/backoff/blob/a78d3804c2c84f0a3178648138442c9b07665bda/exponential.go#L76
	// DefaultInitialInterval     = 500 * time.Millisecond
	// DefaultRandomizationFactor = 0.5
	// DefaultMultiplier          = 1.5
	// DefaultMaxInterval         = 60 * time.Second
	// DefaultMaxElapsedTime      = 15 * time.Minute

	// Define our exponential backoff params
	backoffParams := backoff.NewExponentialBackOff()
	backoffParams.MaxElapsedTime = time.Hour * 4 // Wait in total at most 4 hours
	backoffParams.MaxInterval = time.Hour        // At most 1 hour in between requests

	// Make our ticker
	ticker := backoff.NewTicker(backoffParams)

	// Declare our variables
	var response *http.Response

	// Build request
	bs, _ := json.Marshal(regInfo)
	req, err := http.NewRequest("POST", regUrl, bytes.NewBuffer(bs))
	if err != nil {
		return response, fmt.Errorf("Error creating new http request: %v", err)
	}

	// Headers
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")

	// Keep looping through our ticker, waiting for it to tell us when to retry
	for range ticker.C {
		// Make our Client
		var httpClient = &http.Client{
			Timeout: time.Second * 10,
		}

		response, err = httpClient.Do(req)

		// If the status code is unauthorized, do not attempt to retry
		if response.StatusCode == http.StatusInternalServerError || response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusNotFound {
			ticker.Stop()
			log.Infof("requestUrl: %s, request: %+v", regUrl, req)
			return response, fmt.Errorf("received response code: %d, not retrying", response.StatusCode)
		}

		if err != nil || response.StatusCode != http.StatusOK {
			continue
		}

		ticker.Stop()
		return response, err
	}

	return nil, errors.New("unable to make post request")
}

func missingResponseFields(resp BZeroRegResponse) ([]string, bool) {
	// Print out a specific message if missing registration data
	missing := []string{}
	if resp.ActivationId == "" {
		missing = append(missing, "Activation ID")
	}
	if resp.ActivationCode == "" {
		missing = append(missing, "Activation Code")
	}
	if resp.ActivationRegion == "" {
		missing = append(missing, "Activation Region")
	}
	if resp.SSMTargetId == "" {
		missing = append(missing, "SSM Target ID")
	}
	if resp.OrgID == "" {
		missing = append(missing, "Organization ID")
	}
	if resp.OrgProvider == "" {
		missing = append(missing, "Organization Provider")
	}

	return missing, len(missing) == 0
}
