package fileuploaddownload

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"github.com/aws/amazon-ssm-agent/agent/appconfig"
	agentContext "github.com/aws/amazon-ssm-agent/agent/context"
	agentContracts "github.com/aws/amazon-ssm-agent/agent/contracts"
	"github.com/aws/amazon-ssm-agent/agent/framework/processor/executer/iohandler"
	"github.com/aws/amazon-ssm-agent/agent/keysplitting"
	kysplContracts "github.com/aws/amazon-ssm-agent/agent/keysplitting/contracts"
	"github.com/aws/amazon-ssm-agent/agent/log"
	mgsContracts "github.com/aws/amazon-ssm-agent/agent/session/contracts"
	"github.com/aws/amazon-ssm-agent/agent/session/datachannel"
	"github.com/aws/amazon-ssm-agent/agent/task"
)

const chunkSizeBytes = 1024 * 40
const pluginTimeout = 5 * time.Minute

type FUDMode int

const (
	Init FUDMode = iota
	Upload
	Download
)

func (m FUDMode) String() string {
	return []string{"Init", "Upload", "Download"}[m]
}

// Signals to execute() to start download procedure
type activateDownloadRequest struct {
	filePath string
}

// Signals to execute() to start uploading procedure
type activateUploadRequest struct {
	expectedHash   string
	finalWritePath string
	uploadChunksCh <-chan kysplContracts.FudStreamedChunkPayload
}

// Plugin is the type for the FUD plugin.
type FileUploadDownloadPlugin struct {
	context     agentContext.T
	dataChannel datachannel.IDataChannel
	ksHelper    keysplitting.IKeysplittingHelper
	mode        FUDMode

	// Channels to signal execute() what to do depending on the action received
	activateDownloadCh chan activateDownloadRequest
	activateUploadCh   chan activateUploadRequest

	// Initialized when mode = Upload.
	uploadedChunksCh chan kysplContracts.FudStreamedChunkPayload

	// Channel is closed when execute() exits
	doneCh chan struct{}

	targetUser string
	targetUID  int
	targetGID  int
}

// Returns parameters required for CLI to start session
func (p *FileUploadDownloadPlugin) GetPluginParameters(parameters interface{}) interface{} {
	return parameters
}

// FUD plugin requires handshake to establish session
func (p *FileUploadDownloadPlugin) RequireHandshake() bool {
	return true
}

// NewPlugin returns a new instance of the FUD Plugin.
func NewPlugin(context agentContext.T, targetUser string) (*FileUploadDownloadPlugin, error) {
	if targetUser == "" {
		return &FileUploadDownloadPlugin{}, fmt.Errorf("targetUser cannot be empty")
	}

	user, err := user.Lookup(targetUser)
	if err != nil {
		return &FileUploadDownloadPlugin{}, fmt.Errorf("targetUser could not be looked up: %v", err)
	}
	uid, err := strconv.Atoi(user.Uid)
	if err != nil {
		return &FileUploadDownloadPlugin{}, fmt.Errorf("failed to convert uid to integer: %v", err)
	}
	gid, err := strconv.Atoi(user.Gid)
	if err != nil {
		return &FileUploadDownloadPlugin{}, fmt.Errorf("failed to convert primary gid to integer: %v", err)
	}

	log := context.Log()
	if helper, err := keysplitting.Init(log); err == nil {
		var plugin = FileUploadDownloadPlugin{
			context:  context,
			ksHelper: helper,
			mode:     Init,
			// Buffer with capacity of 1 in rare case that fud-download or
			// fud-upload DATA action comes in faster than execute is called
			activateDownloadCh: make(chan activateDownloadRequest, 1),
			activateUploadCh:   make(chan activateUploadRequest, 1),
			doneCh:             make(chan struct{}),
			targetUser:         targetUser,
			targetUID:          uid,
			targetGID:          gid,
		}
		return &plugin, nil
	} else {
		return &FileUploadDownloadPlugin{}, err
	}
}

// Name returns the name of FUD Plugin
func (p *FileUploadDownloadPlugin) name() string {
	return appconfig.PluginNameFileUploadDownload
}

// Execute establishes a processing loop that handles events related to the FUD
// plugin's execution. It triggers the goroutine to start the download/upload
// procedure when the respective fud action is received from the data channel.
func (p *FileUploadDownloadPlugin) Execute(
	config agentContracts.Configuration,
	cancelFlag task.CancelFlag,
	output iohandler.IOHandler,
	dataChannel datachannel.IDataChannel) {

	log := p.context.Log()
	p.dataChannel = dataChannel
	defer func() {
		if err := recover(); err != nil {
			log.Errorf("Error occurred while executing plugin %s: \n%v", p.name(), err)
			log.Errorf("Stacktrace:\n%s", debug.Stack())
			os.Exit(1)
		}
	}()

	if cancelFlag.ShutDown() {
		output.MarkAsShutdown()
	} else if cancelFlag.Canceled() {
		output.MarkAsCancelled()
	} else {
		p.execute(config, cancelFlag, output)
	}
}

// Execute establishes a processing loop that handles events related to the FUD
// plugin's execution. It triggers the goroutine to start the download/upload
// procedure when the respective fud action is received from the data channel.
func (p *FileUploadDownloadPlugin) execute(
	config agentContracts.Configuration,
	cancelFlag task.CancelFlag,
	output iohandler.IOHandler) {
	log := p.context.Log()
	log.Infof("Plugin %s started", p.name())
	defer log.Info("FUD execution complete")

	// Signal plugin is done
	defer close(p.doneCh)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Catch signals and send a signal to the "sigs" chan if it triggers
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGQUIT)

	// Cancel if signal is caught
	go func() {
		sig := <-sigs
		log.Infof("FUD-caught signal to terminate: %v", sig)
		cancel()
	}()

	// Goroutine for watching cancel flag
	// Cancels ctx
	go func() {
		cancelState := cancelFlag.Wait()
		if cancelFlag.Canceled() {
			log.Debug("Cancel flag set to cancelled in session")
			cancel()
		}
		log.Debugf("Cancel flag set to %v in session", cancelState)
	}()

	// Note that the channel is buffered, so the send in the FUD-download/upload
	// goroutine is nonblocking. This is a common pattern to prevent goroutine
	// leaks in case the channel is never read (e.g. plugin is cancelled)
	errCh := make(chan error, 1)

	// Setup 5 minute timeout
	timer := time.NewTimer(pluginTimeout)

	// Select statement will block until:
	// (1) Receiving a DATA with action: "fud/download" or "fud/upload".
	// (2) Context being cancelled (e.g. Cancel flag being set by AWS, signal caught).
	// (3) Timeout which will be hit if "fud/download" not received,
	// "fud/upload" not received, or context not cancelled within 5 minutes of
	// plugin start.
	//
	// In cases (2) and (3), the plugin exits immediately. In case (1), we break
	// out of the select statement and wait for the respective fud/download or
	// fud/upload goroutines to finish.
	select {
	case req := <-p.activateDownloadCh:
		// Stop the timer
		if !timer.Stop() {
			<-timer.C
		}
		log.Debugf("Start separate go routine to stream file for downloading")
		go func() {
			err := p.sendStreamedFile(ctx, req.filePath)
			if err != nil {
				errMsg := fmt.Sprintf("download failed with error: %v", err.Error())
				sendErr := p.dataChannel.SendKeysplittingMessage(log, p.ksHelper.BuildError(errMsg, kysplContracts.Unknown).(*kysplContracts.KeysplittingError).Content)
				if sendErr != nil {
					err = fmt.Errorf("error sending error msg to user during fud/download. download error: %v; send error: %v", err, sendErr)
				}
			}
			errCh <- err
		}()
		break
	case req := <-p.activateUploadCh:
		// Stop the timer
		if !timer.Stop() {
			<-timer.C
		}
		log.Debugf("Start separate go routine to process incoming file chunks for upload")
		go func() {
			err := p.receiveStreamedFile(ctx, req.expectedHash, req.finalWritePath, req.uploadChunksCh)
			if err != nil {
				errMsg := fmt.Sprintf("upload failed with error: %v", err.Error())
				sendErr := p.dataChannel.SendKeysplittingMessage(log, p.ksHelper.BuildError(errMsg, kysplContracts.Unknown).(*kysplContracts.KeysplittingError).Content)
				if sendErr != nil {
					err = fmt.Errorf("error sending error msg to user during fud/upload. upload error: %v; send error: %v", err, sendErr)
				}
			}
			errCh <- err
		}()
		break
	case <-ctx.Done():
		log.Info("FUD plugin execution cancelled before upload/download action received")
		output.SetExitCode(appconfig.SuccessExitCode)
		output.SetStatus(agentContracts.ResultStatusSuccess)
		return
	case <-timer.C:
		log.Info("FUD timeout hit before upload/download action received")
		output.SetExitCode(appconfig.SuccessExitCode)
		output.SetStatus(agentContracts.ResultStatusSuccess)
		return
	}

	// If we reach this point, then one of the fud/upload or fud/download
	// goroutines started. Those goroutines are guaranteed to exit and send on
	// errCh. They exit with one of the following errors: a nil error (i.e
	// upload/download finished succesfully), a context cancelled error, or an
	// application error. All non-nil errors will be sent as a KsErrorMsg to the
	// user before the errCh is filled.
	err := <-errCh
	if errors.Is(err, context.Canceled) {
		log.Info("FUD plugin execution cancelled before upload/download could finish")
		output.SetExitCode(appconfig.SuccessExitCode)
		output.SetStatus(agentContracts.ResultStatusSuccess)
	} else if err != nil {
		output.SetExitCode(appconfig.ErrorExitCode)
		output.SetStatus(agentContracts.ResultStatusFailed)
		log.Errorf("FUD plugin execute() failed with error: %v", err)
	} else {
		// Nil error means plugin completed successfully
		output.SetExitCode(appconfig.SuccessExitCode)
		output.SetStatus(agentContracts.ResultStatusSuccess)
		log.Info("FUD plugin execute() succeeded with no errors")

		// Wait for Bastion to terminate plugin (cancel flag set), or for signal
		// to be caught.
		<-ctx.Done()
	}
}

func (p *FileUploadDownloadPlugin) openAndHashFile(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed opening file to hash: %w", err)
	}
	defer f.Close()
	return p.hashFile(f)
}

func (p *FileUploadDownloadPlugin) hashFile(file *os.File) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", fmt.Errorf("failed to hash file: %v", err)
	}

	// Return hex-encoded SHA-256 hash
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// For handling uploads
func (p *FileUploadDownloadPlugin) receiveStreamedFile(ctx context.Context, expectedHash string, finalWritePath string, uploadChunksCh <-chan kysplContracts.FudStreamedChunkPayload) error {
	log := p.context.Log()
	tempFile, err := ioutil.TempFile(path.Dir(finalWritePath), fmt.Sprintf("fud-%v", time.Now().UTC().Unix()))
	if err != nil {
		return fmt.Errorf("Failed to create temp file for incoming fud upload: %v", err)
	}
	defer tempFile.Close()

	for {
		select {
		case <-ctx.Done():
			log.Info("Got cancel in fud/upload. Deleting temporary file")
			if err := os.Remove(tempFile.Name()); err != nil {
				return fmt.Errorf("Failed to remove temp file used for fud upload: %v", err)
			}
			return ctx.Err()
		case incomingChunk := <-uploadChunksCh:
			if incomingChunk.Offset == -1 {
				log.Debug("Received final chunk in fud/upload")
				// Reached EoF for upload
				// No more chunks should be sent

				// Rewind file descriptor to beginning
				tempFile.Seek(0, io.SeekStart)

				// Hash temp file
				gotHash, err := p.hashFile(tempFile)
				if err != nil {
					return fmt.Errorf("Failed to hash temp file for fud upload: %v", err)
				}

				// Assert that temp file matches expected hash
				if gotHash != expectedHash {
					return fmt.Errorf("DANGER: unexpected hash received during fud/upload. Got: %v. Wanted: %v", gotHash, expectedHash)
				}

				// Move temp file to final destination
				err = os.Rename(tempFile.Name(), finalWritePath)
				if err != nil {
					return fmt.Errorf("Failed to move temp fud upload file to final destination %v: %v", finalWritePath, err)
				}

				// Chown to target user
				err = os.Chown(finalWritePath, p.targetUID, p.targetGID)
				if err != nil {
					return fmt.Errorf("Failed to chown fud upload file to target user: %v", err)
				}

				// Success!
				log.Info("Finished renaming temporary file")

				// Tell the client in another DataAck message that the upload
				// finished successfully
				encodedJsonRespPayload, err := json.Marshal(&kysplContracts.FudUploadActionDataAckUploadCompletePayload{
					ExpectedHash: expectedHash,
				})
				if err != nil {
					return fmt.Errorf("Error occurred while encoding fud/upload upload complete JSON response: %v", err)
				}

				dataAckContent, err := p.ksHelper.BuildDataAckPayload(kysplContracts.FudUpload, string(encodedJsonRespPayload))
				if err != nil {
					return fmt.Errorf("Failed to build data ack payload containing upload complete payload: %v", err)
				}

				err = p.dataChannel.SendKeysplittingMessage(log, dataAckContent)
				if err != nil {
					return fmt.Errorf("Failed to send final upload complete message: %v", err)
				}

				return nil
			} else {
				// Append chunk to temp file
				_, err := tempFile.WriteAt(incomingChunk.Data, int64(incomingChunk.Offset))
				if err != nil {
					return fmt.Errorf("Failed to write incoming fud upload chunk #%v: %v", incomingChunk.Offset, err)
				}
				log.Debugf("Wrote incoming fud/upload chunk with offset #%v", incomingChunk.Offset)
			}
		}
	}
}

// For handling downloads
func (p *FileUploadDownloadPlugin) sendStreamedFile(ctx context.Context, filePath string) error {
	chunksCh := make(chan ChunkResult)
	if err := ReadFileChunkwise(ctx, filePath, chunkSizeBytes, chunksCh); err != nil {
		return err
	}
	log := p.context.Log()

L:
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case chunkResult := <-chunksCh:
			if chunkResult.Error != nil {
				if chunkResult.Error == io.EOF {
					// An EoF error means we've read the file in its entirety
					break L
				}

				// Otherwise, we have a real error
				return fmt.Errorf("chunk result error: %v", chunkResult.Error)
			}

			// Send the chunk as no error occurred when reading
			chunkPayload, err := json.Marshal(&kysplContracts.FudStreamedChunkPayload{
				Data:   chunkResult.Result.Data,
				Offset: chunkResult.Result.Offset,
			})
			if err != nil {
				return fmt.Errorf("Error occurred while encoding fud/download JSON chunk w/ offset %v: %v", chunkResult.Result.Offset, err)
			}

			chunkCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
			defer cancel()
			if err = p.dataChannel.SendStreamDataMessageAndWaitForAck(chunkCtx, log, mgsContracts.Output, chunkPayload); err != nil {
				return fmt.Errorf("Unable to send streamed download FUD chunk: %w", err)
			}
			log.Debugf("Sent fud/download chunk with offset %v", chunkResult.Result.Offset)
		}
	}

	// If the for loop was broken out of, then there are no more chunks to send.
	// Send a final "EoF" message to signal to the client that it can begin
	// reassembling.
	eofPayload, err := json.Marshal(&kysplContracts.FudStreamedChunkPayload{
		Data:   nil,
		Offset: -1,
	})
	if err != nil {
		return fmt.Errorf("Error occurred while encoding fud/download EoF payload")
	}

	eofCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	if err = p.dataChannel.SendStreamDataMessageAndWaitForAck(eofCtx, log, mgsContracts.Output, eofPayload); err != nil {
		return fmt.Errorf("Unable to send EoF download FUD chunk: %v", err)
	}
	log.Debug("Sent final chunk in fud/download")
	return nil
}

func (p *FileUploadDownloadPlugin) handleValidatedDataPayload(dataPayload kysplContracts.DataPayload, log log.T) error {
	errCh := make(chan error, 1)
	go func() {
		// Must call this so that this entire goroutine operates on a real OS
		// thread which will have permissions set to the target user
		runtime.LockOSThread()

		// Drop down to target user's permissions
		// IMPORTANT: Must set gid first before dropping down to unpriv user
		_, _, serr := syscall.Syscall(syscall.SYS_SETGID, uintptr(p.targetGID), 0, 0)
		if serr != 0 {
			errCh <- fmt.Errorf("syscall setgid failed with errcode: %v", serr)
			return
		}
		_, _, serr = syscall.Syscall(syscall.SYS_SETUID, uintptr(p.targetUID), 0, 0)
		if serr != 0 {
			errCh <- fmt.Errorf("syscall setuid failed with errcode: %v", serr)
			return
		}
		log.Debugf("After dropping, real UID is: %d", syscall.Getuid())
		log.Debugf("After dropping, effective UID is: %d", syscall.Geteuid())
		log.Debugf("After dropping, real GID is: %d", syscall.Getgid())
		log.Debugf("After dropping, effective GID is: %d", syscall.Getegid())

		if p.mode != Init {
			errCh <- p.ksHelper.BuildError(fmt.Sprintf("DATA is not acceptable in FUD mode=%v", p.mode), kysplContracts.InvalidPayload)
			return
		}

		switch kysplContracts.KeysplittingAction(dataPayload.Payload.Action) {
		case kysplContracts.FudDownload:
			var fudDownloadActionPayload kysplContracts.FudDownloadActionDataPayload
			if err := json.Unmarshal([]byte(dataPayload.Payload.Payload), &fudDownloadActionPayload); err != nil {
				errCh <- fmt.Errorf("Error occurred while parsing fud/download data payload json: %v", err)
				return
			}

			// Converts *os.PathError to FudErrorPayload
			errConvert := func(err error, defaultMsg string) error {
				if errors.Is(err, os.ErrNotExist) {
					return p.ksHelper.BuildError(fmt.Sprintf("File not found at path: %v", fudDownloadActionPayload.FilePath), kysplContracts.FUDFileDoesNotExist)
				} else if errors.Is(err, os.ErrPermission) {
					return p.ksHelper.BuildError(fmt.Sprintf("User %v does not have permission to read file: %v", p.targetUser, fudDownloadActionPayload.FilePath), kysplContracts.FUDUserDoesNotHavePermission)
				} else {
					return p.ksHelper.BuildError(fmt.Sprintf("%v: %v", defaultMsg, err), kysplContracts.Unknown)
				}
			}

			// Check for file existence
			if _, err := os.Stat(fudDownloadActionPayload.FilePath); err == nil {
				// File exists

				// Hash the file
				hashFileHex, err := p.openAndHashFile(fudDownloadActionPayload.FilePath)
				if err != nil {
					errCh <- errConvert(err, "Failed when hashing file for download")
					return
				}

				encodedJsonRespPayload, err := json.Marshal(&kysplContracts.FudDownloadActionDataAckPayload{
					ExpectedHash: hashFileHex,
					FileName:     filepath.Base(fudDownloadActionPayload.FilePath),
				})
				if err != nil {
					errCh <- fmt.Errorf("Error occurred while encoding fud/download JSON response: %v", err)
					return
				}

				// Set mode to restrict types of incoming messages
				p.mode = Download

				// Signal execute() to handle download request
				p.activateDownloadCh <- activateDownloadRequest{
					filePath: fudDownloadActionPayload.FilePath,
				}

				// ACK the request to download. Plugin will start streaming file
				// in execute().
				errCh <- p.ksHelper.BuildDataAckWithPayload(dataPayload, string(encodedJsonRespPayload))
				return
			} else {
				errCh <- errConvert(err, "Failed when opening file for download")
				return
			}
		case kysplContracts.FudUpload:
			var fudUploadActionPayload kysplContracts.FudUploadActionDataPayload
			if err := json.Unmarshal([]byte(dataPayload.Payload.Payload), &fudUploadActionPayload); err != nil {
				errCh <- fmt.Errorf("Error occurred while parsing fud/upload data payload json: %v", err)
				return
			}

			// Check that destination path is not a folder
			if info, err := os.Stat(fudUploadActionPayload.DestinationPath); err == nil && info.IsDir() {
				errCh <- p.ksHelper.BuildError(fmt.Sprintf("File upload path: %v cannot be a directory", fudUploadActionPayload.DestinationPath), kysplContracts.FUDInvalidDestinationPath)
				return
			}

			// Check target user's permission
			pathDir := path.Dir(fudUploadActionPayload.DestinationPath)
			tempFile, err := ioutil.TempFile(pathDir, fmt.Sprintf("fud-%v", time.Now().UTC().Unix()))
			if err != nil {
				if errors.Is(err, os.ErrPermission) {
					errCh <- p.ksHelper.BuildError(fmt.Sprintf("User %v does not have permission to write file: %v", p.targetUser, fudUploadActionPayload.DestinationPath), kysplContracts.FUDUserDoesNotHavePermission)
					return
				} else if errors.Is(err, os.ErrNotExist) {
					errCh <- p.ksHelper.BuildError(fmt.Sprintf("File upload path: %v contains folders that do not exist", fudUploadActionPayload.DestinationPath), kysplContracts.FUDInvalidDestinationPath)
					return
				} else {
					errCh <- p.ksHelper.BuildError(fmt.Sprintf("Upload path: %v is invalid: %v", fudUploadActionPayload.DestinationPath, err), kysplContracts.FUDInvalidDestinationPath)
					return
				}
			}
			err = os.Remove(tempFile.Name())
			if err != nil {
				errCh <- fmt.Errorf("Error occurred while removing temp file created during fud/upload: %v", err)
				return
			}
			defer tempFile.Close()

			// Setup channel for streaming incoming file chunks
			p.uploadedChunksCh = make(chan kysplContracts.FudStreamedChunkPayload)

			// Restrict type of incoming messages
			p.mode = Upload

			// Signal execute() to handle download request
			p.activateUploadCh <- activateUploadRequest{
				expectedHash:   fudUploadActionPayload.ExpectedHash,
				finalWritePath: fudUploadActionPayload.DestinationPath,
				uploadChunksCh: p.uploadedChunksCh,
			}

			// ACK the request to upload. Plugin will start waiting for incoming
			// chunks on uploadChunksCh channel.
			errCh <- p.ksHelper.BuildDataAckWithPayload(dataPayload, "")
			return
		default:
			errCh <- p.ksHelper.BuildError(fmt.Sprintf("Keysplitting Action Not Recognized: %v", dataPayload.Payload.Action), kysplContracts.KeysplittingActionError)
			return
		}
	}()
	return <-errCh
}

// InputStreamMessageHandler handles incoming messages
func (p *FileUploadDownloadPlugin) InputStreamMessageHandler(log log.T, streamDataMessage mgsContracts.AgentMessage) error {
	log.Infof("[Keysplitting] %v Message received by FileUploadDownload", mgsContracts.PayloadType(streamDataMessage.PayloadType))

	switch mgsContracts.PayloadType(streamDataMessage.PayloadType) {

	case mgsContracts.Syn:
		if p.mode != Init {
			return p.ksHelper.BuildError(fmt.Sprintf("SYN is not acceptable in FUD mode=%v", p.mode), kysplContracts.InvalidPayload)
		}
		log.Infof("[Keysplitting-FUD] Syn Payload Received: %v", string(streamDataMessage.Payload))
		return p.ksHelper.ProcessSyn(streamDataMessage.Payload)

	case mgsContracts.Data:
		log.Infof("[Keysplitting-FUD] Data Payload Received: %v", string(streamDataMessage.Payload))

		if datapayload, err := p.ksHelper.ValidateDataMessage(streamDataMessage.Payload); err == nil {
			return p.handleValidatedDataPayload(datapayload, log)
		} else {
			return err
		}
	case mgsContracts.Output:
		if p.mode != Upload {
			errMsg := fmt.Sprintf("Output data is not acceptable in FUD mode=%v", p.mode)
			log.Error(errMsg)
			return p.ksHelper.BuildError(errMsg, kysplContracts.InvalidPayload)
		}

		// Decode JSON
		var chunkPayload kysplContracts.FudStreamedChunkPayload
		if err := json.Unmarshal(streamDataMessage.Payload, &chunkPayload); err != nil {
			message := fmt.Sprintf("Error occurred while parsing upload chunk payload json: %v", err)
			return p.ksHelper.BuildError(message, kysplContracts.InvalidPayload)
		}

		// Channel p.uploadedChunksCh is setup when we are in Upload mode
		select {
		case p.uploadedChunksCh <- chunkPayload:
			log.Debugf("[keysplitting-FUD] Sent chunk with offset %v for processing", chunkPayload.Offset)
			return nil
		case <-p.doneCh:
			log.Infof("[keysplitting-FUD] Plugin execution finished. Cannot send chunk %v as no one is listening", chunkPayload.Offset)
			return nil
		}
	default: // fail secure
		message := fmt.Sprintf("This Agent requires a correctly formatted Keysplitting message to communicate")
		return p.ksHelper.BuildError(message, kysplContracts.InvalidPayload)
	}
}
