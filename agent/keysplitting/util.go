// Package built for containing keysplitting helper methods
// Built by BastionZero

package keysplitting

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"

	"golang.org/x/crypto/sha3"

	mgsContracts "github.com/aws/amazon-ssm-agent/agent/session/contracts"
	oidc "github.com/coreos/go-oidc/oidc"
)

const (
	TargetPublicKey  = "thisisthetargetspublickey"
	targetPrivateKey = "buuts" // This is literally ridiculous but Go makes variables that start in lowercase "unexported" aka private
	orgID

	googleJwkUrl = "https://www.googleapis.com/oauth2/v3/certs"
	googleIss    = "https://accounts.google.com"
)

// If this is the beginning of the hash chain, then we select a random value, otherwise
// we use the hash of the previous value to maintain log immutability
func GetNonce(hashpointer string) string {
	if hashpointer != "" {
		b := make([]byte, 32) // 32 to make it same length as hash pointer
		rand.Read(b)

		return base64.StdEncoding.EncodeToString(b)
	}

	return hashpointer
}

func isKeysplittingPayload(a interface{}) bool {
	switch a.(type) {
	case mgsContracts.SynPayloadPayload:
		return true
	case mgsContracts.SynAckPayloadPayload:
		return true
	case mgsContracts.DataPayloadPayload:
		return true
	case mgsContracts.DataAckPayloadPayload:
		return true
	case mgsContracts.BZECert:
		return true
	default:
		return false
	}
}

// Function will accept any type of variable but will only hash strings or byte(s)
// returns a base64 encoded string because otherwise its unprintable nonsense
func Hash(a interface{}) (string, error) {
	switch v := a.(type) {
	case string:
		b, _ := a.(string) // extra type assertion required to hash
		hash := sha3.Sum256([]byte(b))
		return base64.StdEncoding.EncodeToString(hash[:]), nil // This returns type [32]byte but we want a slice so we [:]
	case []byte:
		b, _ := a.([]byte)
		hash := sha3.Sum256(b)
		return base64.StdEncoding.EncodeToString(hash[:]), nil
	default:
		return "", fmt.Errorf("Error only strings and bytes are hashable.  Provided type: %v", v)
	}
}

// Slightly genericized but only accepts Keysplitting structs so any payloads or bzecert
// and returns the base64-encoded string of the hash the raw json string value
func HashStruct(payload interface{}) (string, error) {
	var err error
	var rawpayload []byte

	if isKeysplittingPayload(payload) {
		rawpayload, err = json.Marshal(payload)

		if err != nil {
			return "", fmt.Errorf("Error occurred while marshalling PayloadPayload json: %v", err)
		} else {
			return Hash(rawpayload)
		}
	} else {
		return "", fmt.Errorf("Tried to hash payload of unhandled type %T", payload)
	}
}

// Currently just a pass-through but eventually the hub of operations
func VerifyBZECert(cert mgsContracts.BZECert) error {
	return verifyIdToken(cert)
}

func verifyAuthNonce(cert mgsContracts.BZECert, authNonce string) error {
	nonce := cert.ClientPublicKey + cert.Rand + cert.SignatureOnRand
	hash, _ := Hash(nonce)

	if authNonce == hash {
		return nil
	} else {
		return fmt.Errorf("Invalid nonce in BZECert")
	}
}

// This function verifies Google issued id_tokens
func verifyIdToken(cert mgsContracts.BZECert) error {
	rawtoken := cert.InitialIdToken
	ctx := context.TODO()
	config := &oidc.Config{
		SkipClientIDCheck: true,
		// SupportedSigningAlgs: []string{RS256, ES512},
	}

	keySet := oidc.NewRemoteKeySet(ctx, googleJwkUrl)
	verifier := oidc.NewVerifier(googleIss, keySet, config)

	token, err := verifier.Verify(ctx, rawtoken)
	if err != nil {
		return fmt.Errorf("id_token verification error: Malformed JWT token")
	}

	// the claims we care about checking
	var claims struct {
		EmailVerified bool   `json:"email_verified"`
		Org           string `json:"hd"`
		Nonce         string `json:"nonce"`
	}

	if err := token.Claims(&claims); err != nil { // parse token into claims object
		return fmt.Errorf("id_token verification error: id_token does not have claims: hd and email_verified")
	} else {
		if !claims.EmailVerified {
			return fmt.Errorf("id_token verification error: Email not verified")
		}
		if err = verifyAuthNonce(cert, claims.Nonce); err != nil {
			return err
		}
	}

	if _, err := keySet.VerifySignature(ctx, rawtoken); err != nil {
		return fmt.Errorf("id_token verification error: Invalid signature on JWT")
	} else {
		return nil
	}
}
