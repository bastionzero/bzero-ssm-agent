// Copyright 2021 BastionZero Inc.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Keysplitting Type Definitions
package contracts

import "errors"

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
	Type            string `json:"type"`
	Action          string `json:"action"`
	TargetPublicKey string `json:"targetPublicKey"`
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

// Metrics Message for returning agent metrics data
type MetricsPayload struct {
	StartTime      int64  `json:"startTime"`
	EndTime        int64  `json:"endTime"`
	DeltaMS        int64  `json:"deltaMS"`
	Service        string `json:"service"`
	Description    string `json:"description"`
	ChannelId      string `json:"channelId"`
	SequenceNumber int    `json:"sequenceNumber"`
}

// This will help us fix and control the defined actions any user can take
type KeysplittingAction string

const (
	SshOpen     KeysplittingAction = "ssh/open"
	SshClose    KeysplittingAction = "ssh/close"
	ShellOpen   KeysplittingAction = "shell/open"
	ShellClose  KeysplittingAction = "shell/close"
	ShellInput  KeysplittingAction = "shell/input"
	ShellResize KeysplittingAction = "shell/resize"
	FudDownload KeysplittingAction = "fud/download"
	FudUpload   KeysplittingAction = "fud/upload"
)

type FudStreamedChunkPayload struct {
	Data   []byte `json:"data"`
	Offset int    `json:"offset"`
}

type FudDownloadActionDataPayload struct {
	FilePath string `json:"filePath"`
}

type FudDownloadActionDataAckPayload struct {
	ExpectedHash string `json:"expectedHash"`
	FileName     string `json:"fileName"`
}

type FudUploadActionDataPayload struct {
	ExpectedHash    string `json:"expectedHash"`
	DestinationPath string `json:"destinationPath"`
}

// FudUploadActionDataAckUploadCompletePayload signifies that the upload
// corresponding to ExpectedHash has finished agent-side with no errors.
type FudUploadActionDataAckUploadCompletePayload struct {
	ExpectedHash string `json:"expectedHash"`
}

type SshOpenActionPayload struct {
	Username  string `json:"username"`
	SshPubKey string `json:"sshPubKey"`
}

type KeysplittingResponseMessageType error

var (
	DataAck KeysplittingResponseMessageType = errors.New("DATAACK")
	SynAck  KeysplittingResponseMessageType = errors.New("SYNACK")
	Error   KeysplittingResponseMessageType = errors.New("ERROR")
)

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
	BZECertInvalidIDToken        KeysplittingErrorType = "BZECertInvalidIDToken"
	BZECertInvalidNonce          KeysplittingErrorType = "BZECertInvalidNonce"
	BZECertUnrecognized          KeysplittingErrorType = "BZECertUnrecognized"
	BZECertInvalidProvider       KeysplittingErrorType = "BZECertProviderError"
	BZECertExpired               KeysplittingErrorType = "BZECertExpired"
	HPointerError                KeysplittingErrorType = "HPointerError"
	SigningError                 KeysplittingErrorType = "SigningError"
	SignatureVerificationError   KeysplittingErrorType = "SignatureVerificationError"
	TargetIdInvalid              KeysplittingErrorType = "TargetIdInvalid"
	HashingError                 KeysplittingErrorType = "HashingError"
	KeysplittingActionError      KeysplittingErrorType = "KeysplittingActionError"
	InvalidPayload               KeysplittingErrorType = "InvalidPayload"
	Unknown                      KeysplittingErrorType = "Unknown"
	ChannelClosed                KeysplittingErrorType = "ChannelClosed"
	OutdatedHPointer             KeysplittingErrorType = "OutdatedHPointer"
	BZECertExpiredInitialIdToken KeysplittingErrorType = "BZECertExpiredInitialIdToken"
	HandlerNotReady              KeysplittingErrorType = "HandlerNotReady"
	FUDFileDoesNotExist          KeysplittingErrorType = "FUDFileDoesNotExist"
	FUDUserDoesNotHavePermission KeysplittingErrorType = "FUDUserDoesNotHavePermission"
	FUDInvalidDestinationPath    KeysplittingErrorType = "FUDInvalidDestinationPath"
)
