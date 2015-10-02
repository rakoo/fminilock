package minilockbox

// Contains a block of ciphertext along with the index of the block and some
// small internal attributes to assist in concurrent encryption and decryption.
// Used at encrypt time as a container for passing encrypted blocks to an
// assembly goroutine, and at decrypt time as a container after parsing chunks
// from the contiguous ciphertext.
type MlBlock struct{
  // Attaching index to each chunk makes it easier to do a fan-out-and-order-later
  // pattern for multicore encryption/decryption.
  Index int

  // This is the block data which includes a leading 4-byte plaintext-length
  // number (little endian) and the ciphertext, which includes a 16-byte overhead.
  // This means the length prefix is 16 bytes short of the actual ciphertext block
  // length: must be manually accounted for when chunking for decryption.
  Block []byte

  // Assist in decryption?
  last bool

  // Ease of management: Include errors in blocks, check at client side.
  err error
}

func (self *MlBlock) BeginsLocation() int {
  return filename_block_length + (self.Index - 1) * block_length
}

func (self *MlBlock) ChunkLength() int {
  // Don't use headers, they can't be trusted!
  return len(self.Block) - (16 + 4)
}
