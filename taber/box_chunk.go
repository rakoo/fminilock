package taber

// Whereas block represents a section of ciphertext, enumeratedChunk represents
// a section of plaintext.
type enumeratedChunk struct {
	index int
	chunk []byte
	err   error
}

func (self *enumeratedChunk) beginsLocation() int {
	return self.index * CHUNK_SIZE
}

func (self *enumeratedChunk) endsLocation() int {
	return self.beginsLocation() + len(self.chunk)
}
