package minilockbox

import (
  "sync"
  "bytes"
  "time"
  "golang.org/x/crypto/nacl/secretbox"
  "github.com/cathalgarvey/go-minilock/minilockutils"
)

func prefixToBlockL(prefix int) int {
  return prefix + secretbox.Overhead + 4
}

// Uses length prefixes to parse miniLock ciphertext and return a slice of
// MlBlock objects for decryption.
func walkCiphertext(ciphertext []byte) ([]MlBlock, error) {
  // Enough room for all full blocks, plus the last block, plus the name block.
  blocks := make([]MlBlock, 0, ((len(ciphertext) - 256) / block_length) + 2)
  block_index := 0
  for loc := 0; loc < len(ciphertext); {
    //fmt.Println("walkCiphertext: loc =", loc)
    prefix_leb := ciphertext[loc:loc+4]
    prefix_int32, err := minilockutils.FromLittleEndian(prefix_leb)
    if err != nil {
      return nil, err
    }
    block_ends := loc + prefixToBlockL(int(prefix_int32))
    if block_ends > len(ciphertext) {
      return nil, minilockutils.BadEncodingError("Block length prefixes indicate a length longer than the actual ciphertext.")
    }
    block := ciphertext[loc:block_ends]
    blocks = append(blocks, MlBlock{Index: block_index, Block: block, err: nil})
    if block_ends == len(ciphertext) {
      break
    }
    loc = block_ends
    block_index = block_index + 1
  }
  blocks[len(blocks) - 1].last = true
  return blocks, nil
}

func decryptBlock(key, base_nonce []byte, block *MlBlock) ([]byte, error) {
  var auth bool
  chunk_nonce, err := makeChunkNonce(base_nonce, block.Index, block.last)
  if err != nil {
    return nil, err
  }
  plaintext := make([]byte, 0, len(block.Block) - (secretbox.Overhead + 4))
  plaintext, auth = secretbox.Open(plaintext, block.Block[4:], minilockutils.NonceToArray(chunk_nonce), minilockutils.KeyToArray(key))
  if !auth {
    return nil, minilockutils.AuthenticationError("Authentication of box failed on opening.")
  }
  return plaintext, nil
}

// Return everything preceding the first null byte of the decrypted file-name block.
func decryptName(key, base_nonce []byte, block *MlBlock) (string, error) {
  fn_bytes, err := decryptBlock(key, base_nonce, block)
  if err != nil {
    return "", err
  }
  // Trim to just the bit preceding the first null, OR the whole thing.
  fn_bytes = bytes.SplitN(fn_bytes, []byte{0}, 2)[0]
  return string(fn_bytes), nil
}

type enumeratedChunk struct{
  index int
  chunk []byte
  err error
}

func (self *enumeratedChunk) beginsLocation() int {
  return self.index * chunk_size
}

func (self *enumeratedChunk) endsLocation() int {
  return self.beginsLocation() + len(self.chunk)
}

func reassemble(plaintext []byte, chunksChan chan *enumeratedChunk, done chan bool) ([]byte, error) {
  for {
    select {
      case echunk := <- chunksChan: {
        if echunk.err != nil {
          return nil, echunk.err
        }
        b := echunk.beginsLocation()
        e := echunk.endsLocation()
        // End is calculated using length prefixes so must be regarded as bad
        if e > len(plaintext) {
          return nil, minilockutils.BadEncodingError("Declared length of chunk would write past end of plaintext slice!")
        }
        if len(echunk.chunk) > len(plaintext[b:e]) {
          return nil, minilockutils.BadProgrammingError("Chunk length is longer than expected slot in plaintext slice.")
        }
        copy(plaintext[b:e], echunk.chunk)
      }
      case <- done: {
        return plaintext, nil
      }
      default: {
        time.Sleep(time.Millisecond * 10)
      }
    }
  }
}

func decryptBlockAsync(key, base_nonce []byte, block *MlBlock, chunksChan chan *enumeratedChunk, wg *sync.WaitGroup) {
  // Insert decryption code here
  var echunk *enumeratedChunk
  chunk, err := decryptBlock(key, base_nonce, block)
  if err != nil {
    echunk = &enumeratedChunk{err: err, index: block.Index - 1}
  } else {
    echunk = &enumeratedChunk{index: block.Index - 1, chunk: chunk}
  }
  chunksChan <- echunk
  wg.Done()
}


// Parse blocks, fan-out using decryptBlock, re-assemble to original plaintext.
func Decrypt(key, base_nonce, ciphertext []byte) (filename string, plaintext []byte, err error) {
  blocks, err := walkCiphertext(ciphertext)
  if err != nil {
    return "", nil, err
  }
  filename, err = decryptName(key, base_nonce, &blocks[0])
  if err != nil {
    return "", nil, err
  }
  chunksChan := make(chan *enumeratedChunk)
  expected_length := 0
  wg := new(sync.WaitGroup)
  for _, block := range blocks[1:] {
    block := block
    expected_length = expected_length + block.ChunkLength()
    wg.Add(1)
    go decryptBlockAsync(key, base_nonce, &block, chunksChan, wg)
  }
  // If chunks are larger than the space allotted in plaintext,
  // function will throw an error.
  plaintext = make([]byte, expected_length)
  // Translates the blocking WaitGroup into non-blocking chan bool "done".
  done := make(chan bool)
  go func(done chan bool, wg *sync.WaitGroup) {
    wg.Wait()
    done <- true
  }(done, wg)
  // Awaits chunks on chunksChan until sent on done.
  plaintext, err = reassemble(plaintext, chunksChan, done)
  if err != nil {
    return "", nil, err
  }
  return filename, plaintext, nil
}
