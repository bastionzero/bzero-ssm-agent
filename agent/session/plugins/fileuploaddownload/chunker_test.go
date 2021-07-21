// Copyright 2021 BastionZero Inc.

package fileuploaddownload

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func randomReader(t *testing.T, numBytes int) (io.Reader, []byte) {
	buf := make([]byte, numBytes)
	_, err := rand.Read(buf)
	if err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}

	return bytes.NewReader(buf), buf
}

// ErrReader returns an io.Reader that returns 0, err from all Read calls. Note:
// Use built-in err reader from iotest package when we move to 1.16
func ErrReader(err error) io.Reader {
	return &errReader{err: err}

}

type errReader struct {
	err error
}

func (r *errReader) Read(p []byte) (int, error) {
	return 0, r.err
}

func Test_ReadError(t *testing.T) {
	// A reader that always returns an error
	r := ErrReader(errors.New("error"))

	chunkSize := 1024
	chunksCh := make(chan ChunkResult)
	go splitReaderIntoChunks(context.Background(), r, chunkSize, chunksCh)

	chunkResult := <-chunksCh
	require.Error(t, chunkResult.Error)
}

func Test_ReadSuccess(t *testing.T) {
	// Generate 10 KiB of random data
	reader, expectedContent := randomReader(t, 1024*10)

	// Split file into 1 KiB chunks
	chunkSize := 1024
	chunksCh := make(chan ChunkResult)
	go splitReaderIntoChunks(context.Background(), reader, chunkSize, chunksCh)

	// Create temp file in test temp dir to hold chunks
	tempDir := t.TempDir()
	file, err := ioutil.TempFile(tempDir, "")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	for chunkResult := range chunksCh {
		// Write chunks at the specified offsets
		if chunkResult.Error == nil {
			if _, err := file.WriteAt(chunkResult.Result.Data, int64(chunkResult.Result.Offset)); err != nil {
				t.Fatalf("failed to write at offset %v: %v", chunkResult.Result.Offset, err)
			}
		} else if chunkResult.Error == io.EOF {
			// No more chunks can come if we receive an EoF
			break
		} else {
			t.Fatalf("received chunk result with error: %v", chunkResult.Error)
		}
	}
	// Assert content is correct (checks that offsets are correct as otherwise
	// the content would not match)
	gotContent, err := ioutil.ReadFile(file.Name())
	if err != nil {
		t.Fatalf("failed to read entire testfile: %v", err)
	}

	require.Equal(t, expectedContent, gotContent)
}
