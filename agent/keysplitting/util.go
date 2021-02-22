// Package built for containing keysplitting helper methods
// Built by BastionZero

package keysplitting

import (
	"crypto/sha256"
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
// return hex value ([32]byte)
func GenerateNonce(hashpointer [32]byte) [32]byte {
	if hashpointer != [32]byte{} {
		b := make([]byte, 32) // 32 to make it same size as hash pointer
		rand.Read(b)

		var ret [32]byte
		copy(ret[:], b)
		return ret
	}

	return hashpointer
}

// Function will accept any type of variable but will only hash strings or byte(s)
func Hash(a interface{}) ([32]byte, error) {
	switch v := a.(type) {
	case string:
		b, _ := a.(string) // extra type assertion required to hash
		return sha256.Sum256([]byte(b)), nil
	case []byte:
		b, _ := a.([]byte)
		return sha256.Sum256(b), nil
	case [32]byte:
		b, _ := a.([32]byte)
		return sha256.Sum256([]byte(b[:])), nil
	default:
		return [32]byte{}, fmt.Errorf("Error only strings and bytes are hashable.  Provided type: %v", v)
	}
}

// We need to be hashing messages without the signature so I need to figure this out
func HashPayload(payload mgsContracts.SynPayload) ([32]byte, error) {
	rawpayload, err := json.Marshal(payload)
	if err != nil {
		return [32]byte{}, fmt.Errorf("Error occurred while marshalling Synpayload json: %v", err)
	}

	return Hash(rawpayload)
}
