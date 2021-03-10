// Package built for containing keysplitting helper methods
// Built by BastionZero

package keysplitting

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"

	"golang.org/x/crypto/sha3"

	vault "github.com/aws/amazon-ssm-agent/agent/managedInstances/vault/fsvault"
	mgsContracts "github.com/aws/amazon-ssm-agent/agent/session/contracts"
	oidc "github.com/coreos/go-oidc/oidc"
)

const (
	googleUrl    = "https://accounts.google.com"
	microsoftUrl = "https://login.microsoftonline.com/"
	BZeroConfig  = "BZeroConfig" // TODO: change ref in core to this, change agent_parser
)

type KeysplittingHelper struct {
	publicKey  string
	privateKey string

	orgId    string
	provider string

	HPointer         string
	ExpectedHPointer string
	bzeCerts         map[string]mgsContracts.BZECert

	googleIss    string
	microsoftIss string
}

func Init() (KeysplittingHelper, error) {
	// grab values stored on Registration from Vault
	bzeroConfig := map[string]string{}

	config, err := vault.Retrieve(BZeroConfig)
	if err != nil {
		return KeysplittingHelper{}, fmt.Errorf("Error retreiving BZero config: %v", err)
	} else if config == nil {
		return KeysplittingHelper{}, fmt.Errorf("BZero Config file is empty!")
	}

	// Unmarshal the retrieved data
	if err := json.Unmarshal([]byte(config), &bzeroConfig); err != nil {
		return KeysplittingHelper{}, fmt.Errorf("Error retreiving BZero config: %v", err)
	}

	var helper = KeysplittingHelper{
		publicKey:    bzeroConfig["PublicKey"],
		privateKey:   bzeroConfig["PrivateKey"],
		orgId:        bzeroConfig["OrgId"],
		provider:     bzeroConfig["OrganizationProvider"], // Either Google or Microsoft
		bzeCerts:     make(map[string]mgsContracts.BZECert),
		HPointer:     "",
		googleIss:    googleUrl,
		microsoftIss: microsoftUrl + bzeroConfig["OrgId"],
	}

	return helper, nil
}

// If this is the beginning of the hash chain, then we select a random value, otherwise
// we use the hash of the previous value to maintain log immutability
func (k *KeysplittingHelper) GetNonce() string {
	if k.HPointer != "" {
		b := make([]byte, 32) // 32 to make it same length as hash pointer
		rand.Read(b)
		return base64.StdEncoding.EncodeToString(b)
	} else {
		return k.HPointer
	}
}

func isKeysplittingStruct(a interface{}) bool {
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
		return "", fmt.Errorf("Error only strings and []bytes are hashable.  Provided type: %v", v)
	}
}

// Slightly genericized but only accepts Keysplitting structs so any payloads or bzecert
// and returns the base64-encoded string of the hash the raw json string value
func HashStruct(payload interface{}) (string, error) {
	var payloadMap map[string]interface{}

	if isKeysplittingStruct(payload) {
		if rawpayload, err := json.Marshal(payload); err != nil {
			return "", fmt.Errorf("Error occurred while marshalling keysplitting payload: %v", err)
		} else {
			json.Unmarshal(rawpayload, &payloadMap)
			lexicon, _ := json.Marshal(payloadMap) // Make the marshalled json, alphabetical to match client
			return Hash(lexicon)
		}
	} else {
		return "", fmt.Errorf("Tried to hash payload of unhandled type %T", payload)
	}
}

// Currently just a pass-through but eventually the hub of operations
func (k *KeysplittingHelper) VerifyBZECert(cert mgsContracts.BZECert) error {
	if err := k.verifyIdToken(cert.InitialIdToken, cert, true, true); err != nil {
		return fmt.Errorf("Invalid InitialIdToken: %v", err)
		// TODO: Expire this token after 7 days or whatever
	}
	if err := k.verifyIdToken(cert.CurrentIdToken, cert, false, false); err != nil {
		return fmt.Errorf("Invalid CurrentIdToken: %v", err)
	}

	// Add client's BZECert to map of BZECerts
	if bzehash, err := HashStruct(cert); err == nil { // Becase we validate this the error will be in validation
		k.bzeCerts[bzehash] = cert
	}
	return nil
}

func verifyAuthNonce(cert mgsContracts.BZECert, authNonce string) error {
	nonce := cert.ClientPublicKey + cert.SignatureOnRand + cert.Rand
	hash, _ := Hash(nonce)

	if authNonce == hash {
		return nil
	} else {
		return fmt.Errorf("Invalid nonce in BZECert")
	}
}

// This function verifies id_tokens
func (k *KeysplittingHelper) verifyIdToken(rawtoken string, cert mgsContracts.BZECert, skipExpiry bool, verifyNonce bool) error {
	ctx := context.TODO()
	config := &oidc.Config{
		SkipClientIDCheck: true,
		SkipExpiryCheck:   skipExpiry,
		// SupportedSigningAlgs: []string{RS256, ES512},
	}

	issUrl := ""
	switch k.provider {
	case "google":
		issUrl = k.googleIss
	case "microsoft":
		issUrl = k.microsoftIss
	default:
		return fmt.Errorf("Unhandled Provider type, %v", k.provider)
	}

	provider, err := oidc.NewProvider(ctx, issUrl) // requires a discovery document
	if err != nil {
		return fmt.Errorf("Error establishing OIDC provider during validation: %v", err)
	}
	var verifier = provider.Verifier(config)

	// This checks formatting and signature validity
	token, err := verifier.Verify(ctx, rawtoken)
	if err != nil {
		return fmt.Errorf("ID Token verification error: %v", err)
	}

	// Verify Claims
	// the claims we care about checking
	// TODO map out Microsoft claims to and then switch case verification
	var claims struct {
		EmailVerified bool   `json:"email_verified"`
		HD            string `json:"hd"` // Google Org ID
		Nonce         string `json:"nonce"`
		Org           string `json:"tid"` // Microsoft Org ID or something, check!
	}

	if err := token.Claims(&claims); err != nil { // parse token into claims object
		return fmt.Errorf("OIDC verification error in parsing the ID Token: %v", err)
	} else {
		if !claims.EmailVerified {
			return fmt.Errorf("ID Token verification error: user has not verified their email")
		}
		if claims.Org != k.orgId {
			return fmt.Errorf("ID Token verification error: User's org does not match the target's org")
		}
		if err = verifyAuthNonce(cert, claims.Nonce); err != nil && verifyNonce {
			return err
		}
	}

	return nil
}

func (k *KeysplittingHelper) UpdateHPointer(rawpayload interface{}) error {
	if isKeysplittingStruct(rawpayload) {
		if hash, err := HashStruct(rawpayload); err != nil {
			return err
		} else {
			k.HPointer = hash
			return nil
		}
	} else {
		kerr := k.BuildError(fmt.Sprintf("Trying to update hpointer of unacceptable type, %T", rawpayload))
		return &kerr
	}
}

func (k *KeysplittingHelper) BuildError(message string) mgsContracts.KeysplittingError {
	content := mgsContracts.ErrorPayloadPayload{
		Message:  message,
		HPointer: k.HPointer,
	}
	errorContent := mgsContracts.ErrorPayload{
		Payload:   content,
		Signature: "targetsignature",
	}

	return mgsContracts.KeysplittingError{
		Err:     errors.New("ERROR"),
		Content: errorContent,
	}
}

func (k *KeysplittingHelper) BuildSynAck(nonce string, synpayload mgsContracts.SynPayload) mgsContracts.SynAckPayload {
	// Build SynAck message payload
	contentPayload := mgsContracts.SynAckPayloadPayload{
		Type:            "SYNACK",
		Action:          synpayload.Payload.Action,
		Nonce:           nonce,
		HPointer:        k.HPointer,
		TargetPublicKey: k.publicKey,
	}
	synAckContent := mgsContracts.SynAckPayload{
		Payload:   contentPayload,
		Signature: "thisisatargetsignature",
	}

	// Update expectedHPointer aka the hpointer in the next received message to be H(SYNACK)
	k.ExpectedHPointer, _ = HashStruct(contentPayload)

	return synAckContent
}

func (k *KeysplittingHelper) BuildDataAck(datapayload mgsContracts.DataPayload) mgsContracts.DataAckPayload {
	// Build DataAck message payload
	contentPayload := mgsContracts.DataAckPayloadPayload{
		Type:            "DATAACK",
		Action:          datapayload.Payload.Action,
		HPointer:        k.HPointer,
		Payload:         datapayload.Payload.Payload,
		TargetPublicKey: k.publicKey,
	}
	dataAckContent := mgsContracts.DataAckPayload{
		Payload:   contentPayload,
		Signature: "thisisatargetsignature",
	}

	// Update expectedHPointer aka the hpointer in the next received message to be H(DATAACK)
	k.ExpectedHPointer, _ = HashStruct(contentPayload)

	return dataAckContent
}

func (k *KeysplittingHelper) CheckBZECert(certHash string) error {
	if _, ok := k.bzeCerts[certHash]; !ok {
		kerr := k.BuildError(fmt.Sprintf("Invalid BZECert.  Does not match a previously recieved SYN"))
		return &kerr
	} else {
		return nil
	}
}

func (k *KeysplittingHelper) ValidateHPointer(newPointer string) error {
	if k.ExpectedHPointer != newPointer {
		kerr := k.BuildError("Expected Hpointer: %v did not equal received Hpointer %v")
		return &kerr
	} else {
		return nil
	}
}
