// Keysplitting Type Definitions
package contracts

// BZEcert type for parsing client's certificate
type BZECert struct {
	InitialIdToken  string `json:"initialIdToken"`
	CurrentIdToken  string `json:"currentIdToken"`
	ClientPublicKey string `json:"clientPublicKey"`
	Rand            string `json:"rand"`
	SignatureOnRand string `json:"signatureOnRand"`
}

// Message Definitions for Syn, SynAck, Data, DataAck, and Error

// Definition for Client sent Syn message
type SynPayload struct {
	Payload   SynPayloadPayload `json:"payload"`
	Signature string            `json:"signature"`
}

type SynPayloadPayload struct {
	Type     string  `json:"type"`
	Action   string  `json:"action"`
	Nonce    string  `json:"nonce"`
	TargetId string  `json:"targetId"`
	BZECert  BZECert `json:"BZECert"`
}

// The Target Acks Syn messages with SynAck messages
type SynAckPayload struct {
	Payload   SynAckPayloadPayload `json:"payload"`
	Signature string               `json:"signature"`
}

type SynAckPayloadPayload struct {
	Nonce           string `json:"nonce"`
	HPointer        string `json:"hPointer"`
	TargetPublicKey string `json:"targetPublicKey"`
	Type            string `json:"type"`
	Action          string `json:"action"`
}

// Data messages are always received from the client
// and must be preceeded by a Syn message
type DataPayload struct {
	Payload   DataPayloadPayload `json:"payload"`
	Signature string             `json:"signature"`
}

type DataPayloadPayload struct {
	Type     string `json:"type"`
	Action   string `json:"action"`
	TargetId string `json:"targetId"`
	HPointer string `json:"hPointer"`
	BZECert  string `json:"BZECert"` // This is a hash of the BZECert
	Payload  string `json:"payload"`
}

// DataAck message for replying to Data messages
type DataAckPayload struct {
	Payload   DataAckPayloadPayload `json:"payload"`
	Signature string                `json:"signature"`
}

type DataAckPayloadPayload struct {
	Type            string `json:"type"`
	Action          string `json:"action"`
	HPointer        string `json:"hPointer"`
	Payload         string `json:"payload"`
	TargetPublicKey string `json:"targetPublicKey"`
}

// Error Message for sending back keysplitting errors instead of acks
type ErrorPayloadPayload struct {
	Message         string                `json:"message"`
	Type            KeysplittingErrorType `json:"errorType"`
	HPointer        string                `json:"hPointer"`
	TargetPublicKey string                `json:"targetPublicKey"`
}

type ErrorPayload struct {
	Payload   ErrorPayloadPayload `json:"payload"`
	Signature string              `json:"signature"`
}

// This will help us fix and control the defined actions any user can take
type KeysplittingAction string

const (
	SshOpen  KeysplittingAction = "ssh/open"
	SshClose KeysplittingAction = "ssh/close"
)

type SshOpenActionPayload struct {
	Username  string `json:"username"`
	SshPubKey string `json:"sshPubKey"`
}

// This error is to help return the SYNACK, DATACK, or KSERROR in the correct
// Datachannel object.  One of the payload will always be empty and we'll
// switch based on the Err.Error() because Go doesn't have generics yet.
type KeysplittingError struct {
	Err     error
	Content interface{}
}

func (r *KeysplittingError) Error() string {
	return r.Err.Error()
}

type KeysplittingErrorType string

const (
	BZECertInvalidIDToken      KeysplittingErrorType = "BZECertInvalidIDToken"
	BZECertInvalidNonce        KeysplittingErrorType = "BZECertInvalidNonce"
	BZECertUnrecognized        KeysplittingErrorType = "BZECertInvalidHash"
	BZECertInvalidProvider     KeysplittingErrorType = "BZECertProviderError"
	HPointerError              KeysplittingErrorType = "HPointerError"
	SigningError               KeysplittingErrorType = "SigningError"
	SignatureVerificationError KeysplittingErrorType = "SignatureVerificationError"
	TargetIdInvalid            KeysplittingErrorType = "TargetIdInvalid"
	HashingError               KeysplittingErrorType = "HashingError"
	KeysplittingActionError    KeysplittingErrorType = "KeysplittingActionError"
	InvalidPayload             KeysplittingErrorType = "InvalidPayload"
)
