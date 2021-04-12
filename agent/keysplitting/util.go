// Package built for containing keysplitting helper methods
// Built by BastionZero

package keysplitting

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	ed "crypto/ed25519"

	"golang.org/x/crypto/sha3"

	kysplContracts "github.com/aws/amazon-ssm-agent/agent/keysplitting/contracts"
	"github.com/aws/amazon-ssm-agent/agent/log"
	vault "github.com/aws/amazon-ssm-agent/agent/managedInstances/vault/fsvault"
	oidc "github.com/coreos/go-oidc/oidc"
)

const (
	googleUrl    = "https://accounts.google.com"
	microsoftUrl = "https://login.microsoftonline.com"
	// this is the tenant id Microsoft uses when the account is a personal account (not a work/school account)
	// https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens#payload-claims)
	microsoftPersonalAccountTenantId = "9188040d-6c67-4c5b-b112-36a304b66dad"
	BZeroConfig                      = "BZeroConfig"
	week                             = time.Hour * 168 // 168 hours = 7 days
)

type KeysplittingHelper struct {
	log log.T

	publicKey  string
	privateKey string

	orgId    string
	provider string

	googleIss    string `default:""`
	microsoftIss string `default:""`

	HPointer         string `default:""`
	ExpectedHPointer string
	bzeCerts         map[string]kysplContracts.BZECert
}

func Init(log log.T) (KeysplittingHelper, error) {
	// grab values stored on Registration from Vault
	bzeroConfig := map[string]string{}

	config, err := vault.Retrieve(BZeroConfig)
	if err != nil {
		return KeysplittingHelper{}, fmt.Errorf("[Keysplitting] Error retreiving BZero config: %v", err)
	} else if config == nil {
		return KeysplittingHelper{}, fmt.Errorf("[Keysplitting] BZero Config file is empty!")
	}

	// Unmarshal the retrieved data
	if err := json.Unmarshal([]byte(config), &bzeroConfig); err != nil {
		return KeysplittingHelper{}, fmt.Errorf("[Keysplitting] Error retreiving BZero config: %v", err)
	}

	var helper = KeysplittingHelper{
		log:          log,
		publicKey:    bzeroConfig["PublicKey"],
		privateKey:   bzeroConfig["PrivateKey"],
		orgId:        bzeroConfig["OrganizationID"],
		provider:     bzeroConfig["OrganizationProvider"], // Either google or microsoft
		bzeCerts:     make(map[string]kysplContracts.BZECert),
		googleIss:    googleUrl,
		microsoftIss: getMicrosoftIssuerUrl(bzeroConfig["OrganizationID"]),
	}

	log.Infof("[Keysplitting] Keysplitting Initiated.")

	return helper, nil
}

func getMicrosoftIssuerUrl(orgId string) string {
	// Handles personal accounts by using microsoftPersonalAccountTenantId as the tenantId
	// see https://github.com/coreos/go-oidc/issues/121
	tenantId := ""
	if orgId == "None" {
		tenantId = microsoftPersonalAccountTenantId
	} else {
		tenantId = orgId
	}

	return microsoftUrl + "/" + tenantId + "/v2.0"
}

func (k *KeysplittingHelper) ProcessSyn(payload []byte) error {
	var synpayload kysplContracts.SynPayload

	if err := json.Unmarshal(payload, &synpayload); err != nil {
		// not a keysplitting error, also we can't possibly have the hpointer so it wouldn't be possible to associate the error with the correct message
		message := fmt.Sprintf("Error occurred while parsing SynPayload json: %v", err)
		// Is it icky that anyone can send a Syn or Data payload and get back the current state of the hpointer? Am I overreacting? -lucie
		return k.BuildError(message, kysplContracts.InvalidPayload)
	}
	k.log.Infof("[Keysplitting] Syn Payload Unmarshalled")

	// Get nonce either rand or hpointer (if there is one)
	nonce := k.GetNonce()

	// Update hpointer so we have it for the error messages
	if err := k.UpdateHPointer(synpayload.Payload); err != nil {
		return err
	}

	// pretty legit BZECert verification
	if err := k.VerifyBZECert(synpayload.Payload.BZECert); err != nil {
		return err
	}
	k.log.Infof("[Keysplitting] BZE Certificate Verified")

	// Client Signature verification
	bzehash, _ := k.HashStruct(synpayload.Payload.BZECert)
	if err := k.VerifySignature(synpayload.Payload, synpayload.Signature, bzehash); err != nil {
		return err
	}
	k.log.Infof("[Keysplitting] Client Signature on Syn Message Verified")

	// Validate that TargetId == Hash(pubkey)
	if err := k.VerifyTargetId(synpayload.Payload.TargetId); err != nil {
		return err
	}
	k.log.Infof("[Keysplitting] TargetID from Syn Message Verified")

	// Tells parent Datachannel object to send SYNACK message with specified payload
	k.log.Infof("[Keysplitting] Sending SynAck Message...")
	return k.BuildSynAck(nonce, synpayload)
}

func (k *KeysplittingHelper) ValidateDataMessage(datapayload kysplContracts.DataPayload) error {
	// Update hpointer, needs to be done asap for error reporting purposes
	if err := k.UpdateHPointer(datapayload.Payload); err != nil {
		return err
	}

	// Make sure BZECert hash matches existing hash
	// In the future we should be getting a hash here that we can easily lookup in the map
	if err := k.CheckBZECert(datapayload.Payload.BZECert); err != nil {
		return err
	}
	k.log.Infof("[Keysplitting] BZE Certificate Validated")

	// Verify client signature
	if err := k.VerifySignature(datapayload.Payload, datapayload.Signature, datapayload.Payload.BZECert); err != nil {
		return err
	}
	k.log.Infof("[Keysplitting] Client Signature on Data Message Verified")

	// Validate hash pointer
	if err := k.VerifyHPointer(datapayload.Payload.HPointer); err != nil {
		return err
	}

	// Validate that TargetId == Hash(pubkey)
	if err := k.VerifyTargetId(datapayload.Payload.TargetId); err != nil {
		return err
	}
	k.log.Infof("[Keysplitting] TargetID from Data Message Verified")

	return nil
}

// If this is the beginning of the hash chain, then we create a nonce with a random value,
// otherwise we use the hash of the previous value to maintain the hash chain and immutability
func (k *KeysplittingHelper) GetNonce() string {
	if k.HPointer == "" {
		b := make([]byte, 32) // 32-length byte array, to make it same length as hash pointer
		rand.Read(b)          // populate with random bytes
		return base64.StdEncoding.EncodeToString(b)
	} else {
		return k.HPointer
	}
}

func isKeysplittingStruct(a interface{}) bool {
	switch a.(type) { // switch on a's type
	case kysplContracts.SynPayloadPayload:
		return true
	case kysplContracts.SynAckPayloadPayload:
		return true
	case kysplContracts.DataPayloadPayload:
		return true
	case kysplContracts.DataAckPayloadPayload:
		return true
	case kysplContracts.ErrorPayloadPayload:
		return true
	case kysplContracts.BZECert:
		return true
	default:
		return false
	}
}

// Function will accept any type of variable but will only hash strings or byte(s)
// returns a base64 encoded string because otherwise its unprintable nonsense
func (k *KeysplittingHelper) Hash(a interface{}) (string, error) {
	switch a.(type) {
	case string:
		aString, _ := a.(string) // extra type assertion required to hash
		hash := sha3.Sum256([]byte(aString))
		return base64.StdEncoding.EncodeToString(hash[:]), nil // This returns type [32]byte but we want a slice so we [:]
	case []byte:
		aBytes, _ := a.([]byte)
		hash := sha3.Sum256(aBytes)
		return base64.StdEncoding.EncodeToString(hash[:]), nil
	default:
		return "", fmt.Errorf("Error only strings and []bytes are hashable.  Provided type: %T", a)
	}
}

func safeMarshal(t interface{}) (error, []byte) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(t)
	return err, buffer.Bytes()
}

// Slightly genericized but only accepts Keysplitting structs so any payloads or bzecert
// and returns the base64-encoded string of the hash the raw json string value
func (k *KeysplittingHelper) HashStruct(payload interface{}) (string, error) {
	var payloadMap map[string]interface{}

	if isKeysplittingStruct(payload) {
		if err, rawpayload := safeMarshal(payload); err != nil {
			return "", fmt.Errorf("Error occurred while marshalling keysplitting payload: %v", err)
		} else {
			json.Unmarshal(rawpayload, &payloadMap)
			_, lexicon := safeMarshal(payloadMap) // Make the marshalled json, alphabetical to match client
			k.log.Infof("[Keysplitting] hashing: %s", lexicon)

			// This is because javascript translates CTRL + L as \f and golang translates it as \u000c.
			// Gotta hash the same value to get matching signatures.
			safeLexicon := strings.Replace(string(lexicon), "\\u000c", "\\f", -1)
			return k.Hash(safeLexicon)
		}
	} else {
		return "", fmt.Errorf("Tried to hash payload of unhandled type %T", payload)
	}
}

func (k *KeysplittingHelper) VerifyBZECert(cert kysplContracts.BZECert) error {
	if err := k.verifyIdToken(cert.InitialIdToken, cert, true, true); err != nil {
		return err
	}
	if err := k.verifyIdToken(cert.CurrentIdToken, cert, false, false); err != nil {
		return err
	}

	// Add client's BZECert to map of BZECerts
	// Because we have already marshalled the payload we know that the BZECert is well formed
	bzehash, _ := k.HashStruct(cert)
	k.bzeCerts[bzehash] = cert
	k.log.Infof("[Keysplitting] BZECert Validated")

	// Detailed log reporting
	bzejson, _ := json.Marshal(cert)
	k.log.Infof("[Keysplitting] BZECerts updated, %v: %v", bzehash, string(bzejson))

	return nil
}

// This function takes in the BZECert, extracts all fields for verifying the AuthNonce (sent as
//  part of the ID Token).  Returns nil if nonce is verified, else returns an error of type KeysplittingError
func (k *KeysplittingHelper) verifyAuthNonce(cert kysplContracts.BZECert, authNonce string) error {
	nonce := cert.ClientPublicKey + cert.SignatureOnRand + cert.Rand
	nonceHash, _ := k.Hash(nonce)

	// check nonce is equal to what is expected
	if authNonce != nonceHash {
		return k.BuildError("Nonce in ID token does not match calculated nonce hash", kysplContracts.BZECertInvalidNonce)
	}

	decodedRand, err := base64.StdEncoding.DecodeString(cert.Rand)
	if err != nil {
		return k.BuildError("Nonce is not base64 encoded", kysplContracts.BZECertInvalidNonce)
	}
	randHash, _ := k.Hash(decodedRand)

	if !k.verifySignHelper(cert.ClientPublicKey, randHash, cert.SignatureOnRand) {
		return k.BuildError("Invalid signature on rand in BZECert Nonce", kysplContracts.BZECertInvalidNonce)
	}
	return nil
}

// This function verifies id_tokens
func (k *KeysplittingHelper) verifyIdToken(rawtoken string, cert kysplContracts.BZECert, skipExpiry bool, verifyNonce bool) error {
	ctx := context.TODO() // Gives us non-nil empty context
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
		message := fmt.Sprintf("Unhandled Provider type, %v", k.provider)
		return k.BuildError(message, kysplContracts.BZECertInvalidProvider)
	}

	provider, err := oidc.NewProvider(ctx, issUrl) // Any valid issURL requires a discovery document
	if err != nil {
		message := fmt.Sprintf("Error establishing OIDC provider during validation: %v", err)
		return k.BuildError(message, kysplContracts.BZECertInvalidProvider)
	}

	// This checks formatting and signature validity
	verifier := provider.Verifier(config)
	token, err := verifier.Verify(ctx, rawtoken)
	if err != nil {
		message := fmt.Sprintf("ID Token verification error: %v", err)
		return k.BuildError(message, kysplContracts.BZECertInvalidIDToken)
	}

	// Verify Claims

	// the claims we care about checking
	var claims struct {
		HD       string `json:"hd"`    // Google Org ID
		Nonce    string `json:"nonce"` // Bastion Zero issued nonce
		TID      string `json:"tid"`   // Microsoft Tenant ID
		IssuedAt int64  `json:"iat"`   // Unix datetime of issuance
	}

	if err := token.Claims(&claims); err != nil {
		message := fmt.Sprintf("Error parsing the ID Token: %v", err)
		return k.BuildError(message, kysplContracts.BZECertInvalidIDToken)
	} else {
		k.log.Infof("[Keysplitting] ID Token claims: {HD: %s, Nonce: %s, Org: %s}", claims.HD, claims.Nonce, claims.TID)
		k.log.Infof("[Keysplitting] Agent Org Info: {orgID: %s, orgProvider: %s}", k.orgId, k.provider)
	}

	// Manual check to see if InitialIdToken is expired
	if skipExpiry {
		now := time.Now()
		iat := time.Unix(claims.IssuedAt, 0) // Confirmed both Microsoft and Google use Unix
		if now.After(iat.Add(week)) {
			message := fmt.Sprintf("InitialIdToken Expired {Current Time = %v, Token iat = %v}", now, iat)
			return k.BuildError(message, kysplContracts.BZECertInvalidIDToken)
		}
	}

	// Check if Nonce in ID token is formatted correctly
	if verifyNonce {
		if err = k.verifyAuthNonce(cert, claims.Nonce); err != nil {
			return err
		}
	}

	// Only validate org claim if there is an orgId associated with this agent.
	// This will be empty for orgs associated with a personal gsuite/microsoft account
	switch {
	case k.orgId == "None":
		return nil
	case k.provider == "google":
		if k.orgId != claims.HD {
			return k.BuildError("User's OrgId does not match target's expected Google HD", kysplContracts.BZECertInvalidProvider)
		}
	case k.provider == "microsoft":
		if k.orgId != claims.TID {
			return k.BuildError("User's OrgId does not match target's expected Microsoft tid", kysplContracts.BZECertInvalidProvider)
		}
	}

	return nil
}

func (k *KeysplittingHelper) UpdateHPointer(rawpayload interface{}) error {
	if isKeysplittingStruct(rawpayload) {
		hash, _ := k.HashStruct(rawpayload)
		k.HPointer = hash
		return nil
	} else {
		message := fmt.Sprintf("Trying to update hpointer of unacceptable type, %T", rawpayload)
		return k.BuildError(message, kysplContracts.HPointerError)
	}
}

// This function is only to be called from the DataChannel as a catch-all.  It returns an ErrorPayload to
// be sent in case there is a missed KeysplittingError in the keysplitting logic.  It tries to sign the Payload
// but if it can't, that's okay it did its best.
func BuildUnknownErrorPayload(err error) kysplContracts.ErrorPayload {
	content := kysplContracts.ErrorPayloadPayload{
		Message:  err.Error(),
		Type:     kysplContracts.Unknown,
		HPointer: "",
	}

	return kysplContracts.ErrorPayload{
		Payload:   content,
		Signature: "",
	}
}

func (k *KeysplittingHelper) BuildError(message string, errortype kysplContracts.KeysplittingErrorType) error {
	k.log.Errorf("[Keysplitting] " + message) // log error locally before sending

	content := kysplContracts.ErrorPayloadPayload{
		Message:  message,
		Type:     errortype,
		HPointer: k.HPointer,
	}

	errorContent := kysplContracts.ErrorPayload{
		Payload:   content,
		Signature: "",
	}

	return &kysplContracts.KeysplittingError{
		Err:     errors.New("ERROR"),
		Content: errorContent,
	}
}

// Builds a SynAck in response to a specified Syn payload, returns an error so that the parent process
// can return it as an error, even when it's not
func (k *KeysplittingHelper) BuildSynAck(nonce string, synpayload kysplContracts.SynPayload) error {
	// Build SynAck message payload
	contentPayload := kysplContracts.SynAckPayloadPayload{
		Type:            "SYNACK",
		Action:          synpayload.Payload.Action,
		Nonce:           nonce,
		HPointer:        k.HPointer,
		TargetPublicKey: k.publicKey,
	}

	signature, err := k.SignPayload(contentPayload)
	if err != nil {
		return err
	}

	synAckContent := kysplContracts.SynAckPayload{
		Payload:   contentPayload,
		Signature: signature,
	}

	// Update expectedHPointer aka the hpointer in the next received message to be H(SYNACK)
	k.ExpectedHPointer, _ = k.HashStruct(contentPayload)

	return &kysplContracts.KeysplittingError{
		Err:     errors.New("SYNACK"),
		Content: synAckContent,
	}
}

func (k *KeysplittingHelper) BuildDataAck(datapayload kysplContracts.DataPayload) error {
	// Build DataAck message payload
	contentPayload := kysplContracts.DataAckPayloadPayload{
		Type:            "DATAACK",
		Action:          datapayload.Payload.Action,
		HPointer:        k.HPointer,
		Payload:         datapayload.Payload.Payload,
		TargetPublicKey: k.publicKey,
	}

	signature, err := k.SignPayload(contentPayload)
	if err != nil {
		return err
	}

	dataAckContent := kysplContracts.DataAckPayload{
		Payload:   contentPayload,
		Signature: signature,
	}

	// Update expectedHPointer aka the hpointer in the next received message to be H(DATAACK)
	k.ExpectedHPointer, _ = k.HashStruct(contentPayload)

	return &kysplContracts.KeysplittingError{
		Err:     errors.New("DATAACK"),
		Content: dataAckContent,
	}
}

func (k *KeysplittingHelper) CheckBZECert(certHash string) error {
	if _, ok := k.bzeCerts[certHash]; !ok {
		message := fmt.Sprintf("Invalid BZECert.  Does not match a previously recieved SYN {hash: %s}", certHash)
		return k.BuildError(message, kysplContracts.BZECertUnrecognized)
	} else {
		return nil
	}
}

func (k *KeysplittingHelper) VerifyHPointer(newPointer string) error {
	if k.ExpectedHPointer != newPointer {
		message := fmt.Sprintf("Expected Hpointer: %v did not equal received Hpointer %v", k.ExpectedHPointer, newPointer)
		return k.BuildError(message, kysplContracts.OutdatedHPointer)
	} else {
		return nil
	}
}

func (k *KeysplittingHelper) VerifyTargetId(targetid string) error {
	pubKeyBits, _ := base64.StdEncoding.DecodeString(k.publicKey)

	if pubkeyHash, _ := k.Hash(pubKeyBits); pubkeyHash != targetid {
		message := fmt.Sprintf("Recieved Target Id, %v, did not match this target's id, %v", targetid, pubkeyHash)
		return k.BuildError(message, kysplContracts.TargetIdInvalid)
	} else {
		return nil
	}
}

func (k *KeysplittingHelper) VerifySignature(payload interface{}, sig string, bzehash string) error {
	publickey := k.bzeCerts[bzehash].ClientPublicKey

	hash, err := k.HashStruct(payload)
	if err != nil {
		message := fmt.Sprintf("Error hashing payload for signature verification: %v", err)
		return k.BuildError(message, kysplContracts.HashingError)
	}

	if k.verifySignHelper(publickey, hash, sig) {
		return nil
	} else {
		message := fmt.Sprintf("Could not verify signature {Message: %v, Signature: %v, Public Key: %v}", hash, sig, publickey)
		return k.BuildError(message, kysplContracts.SignatureVerificationError)
	}
}

func (k *KeysplittingHelper) SignPayload(payload interface{}) (string, error) {
	keyBytes, _ := base64.StdEncoding.DecodeString(k.privateKey)
	if len(keyBytes) != 64 {
		message := fmt.Sprintf("Invalid private key length: %v", len(keyBytes))
		k.BuildError(message, kysplContracts.SigningError)
	}
	privateKey := ed.PrivateKey(keyBytes)

	hash, err := k.HashStruct(payload)
	if err != nil {
		message := fmt.Sprintf("Error hashing payload to be signed: %v", err)
		return "", k.BuildError(message, kysplContracts.HashingError)
	}
	hashBits, _ := base64.StdEncoding.DecodeString(hash)

	sig := ed.Sign(privateKey, hashBits)
	return base64.StdEncoding.EncodeToString(sig), nil
}

// args:
//    publickey: base64 encoded bytes of an ed25519 public key, length 32
//    message: base64 encoded hash value of length 32
//    sig: base64 encoded ed25519 signature
func (k *KeysplittingHelper) verifySignHelper(publickey string, message string, sig string) bool {
	pubKeyBits, _ := base64.StdEncoding.DecodeString(publickey)
	if len(pubKeyBits) != 32 {
		k.log.Infof("[Keysplitting] Public Key has invalid length %v", len(pubKeyBits))
		return false
	}
	pubkey := ed.PublicKey(pubKeyBits)

	hashBits, _ := base64.StdEncoding.DecodeString(message)

	sigBits, _ := base64.StdEncoding.DecodeString(sig)

	return ed.Verify(pubkey, hashBits, sigBits)
}
