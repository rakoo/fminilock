package minilockbox

import (
//  "fmt"
  "time"
  "sync"
  "golang.org/x/crypto/nacl/secretbox"
  "github.com/cathalgarvey/go-minilock/minilockutils"
)

func makeChunkNonce(base_nonce []byte, chunk_number int, last bool) ([]byte, error) {
  if len(base_nonce) != 16 {
    return nil, minilockutils.BadArgumentError("Length of base_nonce must be 16.")
  }
  n := make([]byte, len(base_nonce) + 8)
  chunk_num_b, err := minilockutils.ToLittleEndian(int32(chunk_number))
  if err != nil {
    return nil, err
  }
  copy(n, base_nonce)
  copy(n[len(base_nonce):], chunk_num_b)
  if last {
    n[len(n)-1] = n[len(n)-1] | 128
  }
  return n, nil
}

func encryptChunk(key, base_nonce, chunk []byte, index int, last bool) (*MlBlock, error) {
  // Handling of last-chunk is done using the chunk nonce,
  chunk_nonce, err := makeChunkNonce(base_nonce, index, last)
  if err != nil {
    return nil, err
  }
  // Make room for the 4-byte length prefix, the ciphertext, plus the ciphertext overhead.
  ciphertext := make([]byte, 4, len(chunk) + secretbox.Overhead + 4)
  // Prepend length.
  bl_len, err := minilockutils.ToLittleEndian(int32(len(chunk)))
  if err != nil {
    return nil, err
  }
  if len(bl_len) > 4 {
    return nil, minilockutils.BadProgrammingError("Chunk length prefix is longer than 4 bytes, would clobber ciphertext.")
  }
  copy(ciphertext, bl_len)
  // Put the ciphertext in the space after the first four bytes.
  ciphertext = secretbox.Seal(ciphertext, chunk, minilockutils.NonceToArray(chunk_nonce), minilockutils.KeyToArray(key))
  // Get 4-byte length prefix, verify it's the right length JIC.
  return &MlBlock{Block: ciphertext, Index: index}, nil
}

// Convenience for the special case.
func prepareNameChunk(filename string) ([]byte, error) {
  // Prepare name
  fn_bytes := []byte(filename)
  if len(fn_bytes) > 256 {
    return nil, minilockutils.BadArgumentError("Filename cannot be longer than 256 bytes: "+filename)
  }
  padded_name := make([]byte, 256, 256)
  copy(padded_name, fn_bytes)
  return padded_name, nil
}

// Chunk up a file and encrypt each chunk separately, returning each chunk through
// block_chan for reassembly. Blocks can and will arrive out of order through block_chan.
func EncryptToChan(filename string, key, base_nonce, file_data []byte, block_chan chan *MlBlock, done chan bool) (err error) {
  if base_nonce == nil {
    base_nonce, err = minilockutils.MakeBaseNonce()
    if err != nil {
      return err
    }
  }
  filename_chunk, err := prepareNameChunk(filename)
  if err != nil {
    return err
  }
  fn_block, err := encryptChunk(key, base_nonce, filename_chunk, 0, false)
  if err != nil {
    return err
  }
  block_chan <- fn_block
  // Get expected chunk number so special treatment of last chunk can be done
  // correctly.
  num_chunks := minilockutils.NumChunks(len(file_data), chunk_size)
  wg := new(sync.WaitGroup)
  for i, chunk := range minilockutils.Chunkify(file_data, chunk_size) {
    block_number := i + 1
    wg.Add(1)
    // Fan out the job of encrypting each chunk. Each ciphertext block gets passed
    // back through block_chan. WaitGroup wg makes sure all goroutines are finished
    // prior to passing back "done".
    go func(key, base_nonce, chunk []byte, block_number int, block_chan chan *MlBlock, wg *sync.WaitGroup){
      var (
        ciphertext *MlBlock
        err error
      )
      if block_number == num_chunks {
        ciphertext, err = encryptChunk(key, base_nonce, chunk, block_number, true)
      } else {
        ciphertext, err = encryptChunk(key, base_nonce, chunk, block_number, false)
      }
      if err != nil {
        ciphertext.err = err
      }
      block_chan <- ciphertext
      wg.Done()
    }(key, base_nonce, chunk, block_number, block_chan, wg)

  }
  wg.Wait()
  done <- true
  return nil
}

// Adds "base_nonce" to public facing version for testing purposes.
func Encrypt(filename string, key, base_nonce, file_data []byte) (ciphertext []byte, err error) {
  if len(key) != 32 {
    return nil, minilockutils.BadArgumentError("Encryption key must be 32 bytes long.")
  }
  // Pre-allocate space to help assemble the ciphertext afterwards..
  num_chunks := minilockutils.NumChunks(len(file_data), chunk_size)
  // Now allocate all but the last block. The last block is *appended* to the
  // output, the others are *copied*.
  // Each block requires 4 for the LE int length prefix, chunk_size for the block,
  // and 16 for the encryption overhead.
  max_length := filename_block_length + (num_chunks * block_length)
  ciphertext = make([]byte, max_length - block_length, max_length)
  // Now fan-out the job of encrypting the file...
  block_chan := make(chan *MlBlock)
  done_chan := make(chan bool)
  go EncryptToChan(filename, key, base_nonce, file_data, block_chan, done_chan)
  // And then fan-in re-assembly.
  for {
    select {
    case block := <-block_chan: {
      if block.err != nil {
        // Blocks may return errors, cancel on any error.
        // This leaves the goroutines running but they ought to run out on their own?
        return nil, block.err
      }
      if block.Index > 0 && block.Index < num_chunks {
        // Find correct location for each chunk and copy in.
        begins := block.BeginsLocation()
        ends := begins + len(block.Block)
        copy(ciphertext[begins:ends], block.Block)
      } else if block.Index == num_chunks {
        ciphertext = append(ciphertext, block.Block...)
      } else {
        // Filename chunk, special case.
        copy(ciphertext, block.Block)
      }
    }
    case <- done_chan: {
      goto encrypt_finished
    }
    default: {
      time.Sleep(time.Millisecond * 10)
    }
    }
  }
  encrypt_finished:
  return ciphertext, nil
}
