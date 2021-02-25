// Package built for containing keysplitting helper methods
// Built by BastionZero

package keysplitting

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"

	mgsContracts "github.com/aws/amazon-ssm-agent/agent/session/contracts"
)

const (
	TargetPublicKey  = "thisisthetargetspublickey"
	targetPrivateKey = "buuts" // This is literally ridiculous but Go makes variables that start in lowercase "unexported" aka private
)

// If this is the beginning of the hash chain, then we select a random value, otherwise
// we use the hash of the previous value to maintain log immutability
func GetNonce(hashpointer string) string {
	if hashpointer != "" {
		b := make([]byte, 32) // 32 to make it same length as hash pointer
		rand.Read(b)

		return hex.EncodeToString(b)
	}

	return hashpointer
}

// Function will accept any type of variable but will only hash strings or byte(s)
// returns a hex encoded string because otherwise its unprintable nonsense
func Hash(a interface{}) (string, error) {
	switch v := a.(type) {
	case string:
		b, _ := a.(string) // extra type assertion required to hash
		hash := sha256.Sum256([]byte(b))
		return hex.EncodeToString(hash[:]), nil // This returns type [32]byte but we want a slice so we [:]
	case []byte:
		b, _ := a.([]byte)
		hash := sha256.Sum256(b)
		return hex.EncodeToString(hash[:]), nil
	default:
		return "", fmt.Errorf("Error only strings and bytes are hashable.  Provided type: %v", v)
	}
}

// Slightly genericized but only accepts payloadpayloads of type SynPayloadPayload and DataPayloadPayload
// and returns the hex-encoded string of the hash the raw json string value
func HashPayloadPayload(payload interface{}) (string, error) {
	var err error
	var rawpayload []byte

	switch v := payload.(type) {
	case mgsContracts.SynPayloadPayload:
		rawpayload, err = json.Marshal(payload)
	case mgsContracts.DataPayloadPayload:
		rawpayload, err = json.Marshal(payload)
	default:
		return "", fmt.Errorf("Tried to hash payload of unhandled type %v", v)
	}

	if err != nil {
		return "", fmt.Errorf("Error occurred while marshalling PayloadPayload json: %v", err)
	} else {
		return Hash(rawpayload)
	}
}
