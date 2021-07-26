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

package fileuploaddownload

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
)

type ChunkResult struct {
	Result Chunk
	Error  error
}

type Chunk struct {
	Data   []byte
	Offset int
}

// ReadFileChunkwise reads a file located at filePath and splits it into chunks
// of size chunkSizeBytes. It returns an error if the OS fails to open the file.
//
// ReadFileChunkwise blocks on sending to chunksRead if the channel is full or
// if it is unbuffered and no goroutine is ready to receive the next chunk. It
// will not block if the context is cancelled.
//
// A ChunkResult with Error == io.EOF will be sent on chunksRead when the file
// has been read in its entirety.
func ReadFileChunkwise(ctx context.Context, filePath string, chunkSizeBytes int, chunksRead chan<- ChunkResult) error {
	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}

	// Start a goroutine to split file into chunks
	go func() {
		defer file.Close()
		reader := bufio.NewReader(file)
		splitReaderIntoChunks(ctx, reader, chunkSizeBytes, chunksRead)
	}()

	return nil
}

func splitReaderIntoChunks(ctx context.Context, reader io.Reader, chunkSizeBytes int, chunksRead chan<- ChunkResult) {
	var offset int = 0
	for {
		buffer := make([]byte, chunkSizeBytes)
		bytesRead, err := reader.Read(buffer)
		if err != nil {
			if err != io.EOF {
				select {
				case chunksRead <- ChunkResult{Result: Chunk{}, Error: err}:
					return
				case <-ctx.Done():
					return
				}
			} else {
				// Hit EOF. Send special result
				select {
				case chunksRead <- ChunkResult{Result: Chunk{}, Error: io.EOF}:
					return
				case <-ctx.Done():
					return
				}
			}
		} else {
			select {
			case chunksRead <- ChunkResult{Result: Chunk{Data: buffer[:bytesRead], Offset: offset}, Error: nil}:
				break
			case <-ctx.Done():
				return
			}

			offset += bytesRead
		}
	}
}
