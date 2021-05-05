package registration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/aws/amazon-ssm-agent/agent/log"
	vault "github.com/aws/amazon-ssm-agent/agent/managedInstances/vault/fsvault"
)

const (
	BZeroConfigStorage    = "BZeroConfig"
	BZeroRegStorage       = "BZeroRegistration"
	BZeroRegErrorExitCode = 234 // Sorry I'm a nerd but this is ascii B + Z

	// Purely internal
	maxRegistrationRetry = 2
	retrySleep           = 5 * time.Second
	httpTimeout          = 10 * time.Second
)

// Struct to allow for backwards/forwards compatability in registration flow
type BZeroRegInfo struct {
	RegID      string `json:"registrationId"`
	RegSecret  string `json:"registrationSecret"`
	TargetName string `json:"instanceName"`
	EnvID      string `json:"environmentId"`
	APIUrl     string `json:"apiUrl"`
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
func Register(log log.T) (BZeroRegResponse, error) {
	// Get Registration Information
	reg, err := grabRegInfo()
	if err != nil {
		log.Error(err.Error())
		return BZeroRegResponse{}, err
	}

	// Try to register
	log.Infof("Making Registration API Request...")
	resp, err := callRegAPI(reg, log)

	if err == nil {
		log.Infof("Successfully Registered Agent on First Attempt!")
		return resp, nil
	} else {
		log.Errorf("Got error on first attempt registering API: %v", err)
	}

	// Trying to re-register if first time fails
	count := 0
	for count <= maxRegistrationRetry && err != nil {
		time.Sleep(retrySleep)
		resp, err = callRegAPI(reg, log)
		count += 1
	}

	// Report outcome of retries
	if err != nil {
		rerr := fmt.Errorf("Failed to register with Bzero after %v tries: %v", maxRegistrationRetry, err)
		log.Error(rerr.Error())
		return BZeroRegResponse{}, rerr
	} else {
		log.Infof("Successfully registered agent with BZero after %v tries", count+1)
		return resp, nil
	}
}

func grabRegInfo() (BZeroRegInfo, error) {
	var regInfo BZeroRegInfo

	regFile, err := vault.Retrieve(BZeroRegStorage)
	if err != nil {
		rerr := fmt.Errorf("Error Retreiving BZero Registration Information: %v", err)
		return BZeroRegInfo{}, rerr
	} else if regFile == nil {
		rerr := fmt.Errorf("BZero Registration Information File is Empty!")
		return BZeroRegInfo{}, rerr
	}

	// Unmarshal the retrieved data
	if err := json.Unmarshal([]byte(regFile), &regInfo); err != nil {
		rerr := fmt.Errorf("Error Marshalling Stored BZero Registration Information: %v", err)
		return BZeroRegInfo{}, rerr
	}

	return regInfo, nil
}

// Hit BZero Registration API to attempt to register
func callRegAPI(reg BZeroRegInfo, log log.T) (BZeroRegResponse, error) {
	// ctx, cancel := context.WithTimeout(context.TODO(), httpTimeout)
	// defer cancel()

	// This is going to give us timeouts on everything
	// Our service is down? Timeout.
	// var netTransport = &http.Transport{
	// 	Dial: (&net.Dialer{
	// 		Timeout: httpTimeout,
	// 	}).Dial,
	// }

	client := &http.Client{
		Timeout: httpTimeout,
	}

	// POST body
	var body map[string]interface{}

	data, _ := json.Marshal(reg)
	json.Unmarshal(data, &body)
	delete(body, "apiUrl") // We want everything from BzeroRegInfo except for the APIUrl
	bs, _ := json.Marshal(body)

	// Create request
	req, err := http.NewRequest("POST", reg.APIUrl, bytes.NewBuffer(bs))
	if err != nil {
		return BZeroRegResponse{}, fmt.Errorf("Error creating new http request: %v", err)
	}

	// Add context to request so we can cancel requests after timeout
	// req = req.WithContext(ctx)

	// Headers
	req.Header.Add("Accept", "text/plain")
	req.Header.Add("Content-Type", "application/json")

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		return BZeroRegResponse{}, fmt.Errorf("Could not complete API request: %v", err)
	}

	// Read response
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return BZeroRegResponse{}, fmt.Errorf("Error reading http POST response bytes: %v", err)
	}

	// Unmarshal response into struct
	var response BZeroRegResponse
	json.Unmarshal(respBytes, &response)

	return response, nil
}
