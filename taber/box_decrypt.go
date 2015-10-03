package taber

import (
	"bytes"
	"golang.org/x/crypto/nacl/secretbox"
	"sync"
	"time"
)

// Uses length prefixes to parse miniLock ciphertext and return a slice of
// block objects for decryption.
func walkCiphertext(ciphertext []byte) ([]block, error) {
	// Enough room for all full blocks, plus the last block, plus the name block.
	blocks := make([]block, 0, ((len(ciphertext)-256)/BLOCK_LENGTH)+2)
	block_index := 0
	for loc := 0; loc < len(ciphertext); {
		//fmt.Println("walkCiphertext: loc =", loc)
		prefix_leb := ciphertext[loc : loc+4]
		prefix_int32, err := fromLittleEndian(prefix_leb)
		if err != nil {
			return nil, err
		}
		block_ends := loc + prefixToBlockL(int(prefix_int32))
		if block_ends > len(ciphertext) {
			return nil, BadLengthPrefixError
		}
		this_block := ciphertext[loc:block_ends]
		blocks = append(blocks, block{Index: block_index, Block: this_block, err: nil})
		if block_ends == len(ciphertext) {
			break
		}
		loc = block_ends
		block_index = block_index + 1
	}
	blocks[len(blocks)-1].last = true
	return blocks, nil
}

func decryptBlock(key, base_nonce []byte, block *block) ([]byte, error) {
	var auth bool
	chunk_nonce, err := makeChunkNonce(base_nonce, block.Index, block.last)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, 0, len(block.Block)-(secretbox.Overhead+4))
	plaintext, auth = secretbox.Open(plaintext, block.Block[4:], nonceToArray(chunk_nonce), keyToArray(key))
	if !auth {
		return nil, BoxAuthenticationError
	}
	return plaintext, nil
}

// Return everything preceding the first null byte of the decrypted file-name block.
func decryptName(key, base_nonce []byte, name_block *block) (string, error) {
	fn_bytes, err := decryptBlock(key, base_nonce, name_block)
	if err != nil {
		return "", err
	}
	// Trim to just the bit preceding the first null, OR the whole thing.
	fn_bytes = bytes.SplitN(fn_bytes, []byte{0}, 2)[0]
	return string(fn_bytes), nil
}

func reassemble(plaintext []byte, chunksChan chan *enumeratedChunk, done chan bool) ([]byte, error) {
	for {
		select {
		case echunk := <-chunksChan:
			{
				if echunk.err != nil {
					return nil, echunk.err
				}
				b := echunk.beginsLocation()
				e := echunk.endsLocation()
				// End is calculated using length prefixes so must be regarded as bad
				if e > len(plaintext) {
					return nil, BoxDecryptionEOPError
				}
				if len(echunk.chunk) > len(plaintext[b:e]) {
					return nil, BoxDecryptionEOSError
				}
				copy(plaintext[b:e], echunk.chunk)
			}
		case <-done:
			{
				return plaintext, nil
			}
		default:
			{
				time.Sleep(time.Millisecond * 10)
			}
		}
	}
}

func decryptBlockAsync(key, base_nonce []byte, this_block *block, chunksChan chan *enumeratedChunk, wg *sync.WaitGroup) {
	// Insert decryption code here
	var echunk *enumeratedChunk
	chunk, err := decryptBlock(key, base_nonce, this_block)
	if err != nil {
		echunk = &enumeratedChunk{err: err, index: this_block.Index - 1}
	} else {
		echunk = &enumeratedChunk{index: this_block.Index - 1, chunk: chunk}
	}
	chunksChan <- echunk
	wg.Done()
}

// Parse blocks, fan-out using decryptBlock, re-assemble to original plaintext.
func decrypt(key, base_nonce, ciphertext []byte) (filename string, plaintext []byte, err error) {
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
	for _, this_block := range blocks[1:] {
		this_block := this_block
		expected_length = expected_length + this_block.ChunkLength()
		wg.Add(1)
		go decryptBlockAsync(key, base_nonce, &this_block, chunksChan, wg)
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

// A structured object returned by Encrypt to go with ciphertexts, which
// provides a method for Decrypting ciphertexts. Can easily be constructed
// from raw data, passed around, serialised, etcetera.
type DecryptInfo struct {
	// Decryption key (32 bytes) and Nonce (24 bytes) required to decrypt.
	Key, BaseNonce []byte
}

func NewDecryptInfo() (*DecryptInfo, error) {
	key, err := makeSymmetricKey()
	if err != nil {
		return nil, err
	}
	nonce, err := makeBaseNonce()
	if err != nil {
		return nil, err
	}
	return &DecryptInfo{Key: key, BaseNonce: nonce}, nil
}

func (self *DecryptInfo) Validate() bool {
	return len(self.Key) == 32 && len(self.BaseNonce) == 16
}

func (self *DecryptInfo) Decrypt(ciphertext []byte) (filename string, plaintext []byte, err error) {
	if !self.Validate() {
		return "", nil, BoxDecryptionVariablesError
	}
	return decrypt(self.Key, self.BaseNonce, ciphertext)
}
