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
	TargetPublicKey = "thisisthetargetspublickey"
)

// If this is the beginning of the hash chain, then we select a random value, otherwise
// we use the hash of the previous value to maintain log immutability
func GenerateNonce(hashpointer string) string {
	if hashpointer != "" {
		b := make([]byte, 32) // 32 to make it same len as hash pointer
		rand.Read(b)

		return hex.EncodeToString(b)
	}

	return hashpointer
}

// Function will accept any type of variable but will only hash strings or byte(s)
//
func HashA(a interface{}) (string, error) {
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

// We need to be hashing messages without the signature so I need to figure this out
func HashPayload(payload mgsContracts.SynPayload) (string, error) {
	rawpayload, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("Error occurred while marshalling Synpayload json: %v", err)
	}

	return HashA(rawpayload)
}
