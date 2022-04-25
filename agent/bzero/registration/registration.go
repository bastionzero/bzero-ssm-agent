package registration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"time"

	"github.com/cenkalti/backoff"

	logger "github.com/aws/amazon-ssm-agent/agent/log"
)

const (
	BZeroConfigStorage    = "BZeroConfig"
	BZeroRegErrorExitCode = 234

	registrationEndpoint         = "targets/ssm/register"
	prodServiceUrl               = "https://cloud.bastionzero.com/" // default
	getConnectionServiceEndpoint = "api/v2/connection-service/url"
)

// This is the data sent to the Reg API
type BZeroRegRequest struct {
	RegSecret  string `json:"registrationSecret"`
	TargetName string `json:"instanceName"`
	EnvId      string `json:"environmentId,omitempty"`
	EnvName    string `json:"environmentName,omitempty"`
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

type GetConnectionServiceResponse struct {
	ConnectionServiceUrl string `json:"connectionServiceUrl"`
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

	// Register with BastionZero
	resp, err := sendRegisterRequest(log, regInfo, serviceUrl)
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

func sendRegisterRequest(log logger.T, regInfo BZeroRegRequest, serviceUrl string) (*http.Response, error) {
	// Declare our variables
	var response *http.Response

	// Marshal the regInfo data so we don't do it every time
	regInfoBytes, err := json.Marshal(regInfo)
	if err != nil {
		return response, fmt.Errorf("could not marshal registration request")
	}

	// Build Registration Endpoint
	if serviceUrl == "" {
		serviceUrl = prodServiceUrl
	}

	log.Infof("Using service url %s", serviceUrl)

	// Get connection service url from bastion
	connectionServiceUrl, connectionServiceUrlErr := getConnectionServiceUrlFromServiceUrl(log, serviceUrl)
	if connectionServiceUrlErr != nil {
		return &http.Response{}, connectionServiceUrlErr
	}

	u, err := url.Parse(connectionServiceUrl)
	if err != nil {
		return response, fmt.Errorf("could not parse connection service url: %s error: %s", connectionServiceUrl, err)
	}
	u.Path = path.Join(u.Path, registrationEndpoint)

	req, err := http.NewRequest("POST", u.String(), bytes.NewBuffer(regInfoBytes))
	if err != nil {
		return response, err
	}

	resp, err := sendRequestWithRetry(log, req)
	if err != nil {
		return resp, err
	}

	return resp, nil
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

func sendRequestWithRetry(log logger.T, req *http.Request) (*http.Response, error) {
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

	for range ticker.C {

		// Make our http Client
		var httpClient = &http.Client{
			Timeout: time.Second * 10,
		}

		// Headers
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Content-Type", "application/json")

		log.Infof("Sending request to %s", req.URL)
		if response, err := httpClient.Do(req); err != nil {
			continue
		} else if response.StatusCode == http.StatusUnauthorized ||
			response.StatusCode == http.StatusUnsupportedMediaType ||
			response.StatusCode == http.StatusGone {

			ticker.Stop()
			return nil, fmt.Errorf("received response code: %d, not retrying", response.StatusCode)
		} else if response.StatusCode != http.StatusOK {
			continue
		} else {
			ticker.Stop()
			return response, nil
		}
	}

	return nil, fmt.Errorf("Failed to successfully make request to: %s", req.URL)
}

func getConnectionServiceUrlFromServiceUrl(log logger.T, serviceUrl string) (string, error) {
	// Make request to bastion to get connection service url
	u, err := url.Parse(serviceUrl)
	if err != nil {
		return "", fmt.Errorf("could not parse service url: %s error: %s", serviceUrl, err)
	}
	u.Path = path.Join(u.Path, getConnectionServiceEndpoint)

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", err
	}

	resp, err := sendRequestWithRetry(log, req)
	if err != nil {
		return "", err
	}

	// Unmarshal the response
	respBytes, readAllErr := ioutil.ReadAll(resp.Body)
	if readAllErr != nil {
		return "", fmt.Errorf("error reading body on get connection service url request: %v", readAllErr)
	}

	var getConnectionServiceResponse GetConnectionServiceResponse
	if err := json.Unmarshal(respBytes, &getConnectionServiceResponse); err != nil {
		return "", fmt.Errorf("malformed getConnectionService response: %s", err)
	}

	return getConnectionServiceResponse.ConnectionServiceUrl, nil
}
