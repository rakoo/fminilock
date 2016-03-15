package taber

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"

	"golang.org/x/crypto/nacl/secretbox"
)

// Return a slice of slices representing <chunk_length> chunks of <data>,
// excepting the last chunk which may be truncated.
func chunkify(data []byte, chunk_length int) [][]byte {
	dlen := len(data)
	num_chunks := numChunks(dlen, chunk_length)
	output := make([][]byte, 0, num_chunks)
	// Populate chunk slices
	for cn := 0; cn < num_chunks; cn++ {
		chunk_begin := cn * chunk_length
		chunk_end := chunk_begin + chunk_length
		if chunk_end > dlen {
			chunk_end = dlen
		}
		this_chunk := data[chunk_begin:chunk_end]
		output = append(output, this_chunk)
	}
	return output
}

func numChunks(data_length, chunk_length int) int {
	num_chunks := data_length / chunk_length
	if (data_length % chunk_length) > 0 {
		num_chunks = num_chunks + 1
	}
	return num_chunks
}

func randBytes(i int) ([]byte, error) {
	rand_bytes := make([]byte, i)
	read, err := rand.Read(rand_bytes)
	if err != nil {
		return nil, err
	}
	if read != i {
		return nil, ErrInsufficientEntropy
	}
	return rand_bytes, nil
}

func makeBaseNonce() ([]byte, error) {
	return randBytes(16)
}

func makeFullNonce() ([]byte, error) {
	return randBytes(24)
}

func makeSymmetricKey() ([]byte, error) {
	return randBytes(32)
}

func nonceToArray(n []byte) *[24]byte {
	na := new([24]byte)
	copy(na[:], n)
	return na
}

func keyToArray(k []byte) *[32]byte {
	ka := new([32]byte)
	copy(ka[:], k)
	return ka
}

func prefixToBlockL(prefix int) int {
	return prefix + secretbox.Overhead + 4
}

func toLittleEndian(i int32) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, i)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func fromLittleEndian(buf []byte) (int32, error) {
	var output int32
	buf_reader := bytes.NewReader(buf)
	err := binary.Read(buf_reader, binary.LittleEndian, &output)
	if err != nil {
		return 0, err
	}
	return output, nil
}

// WipeKeyArray fills a 32-byte array such as used for key material with random bytes.
// It is intended for use with defer to wipe temporary arrays used to contain key material.
func WipeKeyArray(arr *[32]byte) error {
	return wipeByteSlice(arr[:])
}

func wipeByteSlice(bs []byte) error {
	var (
		bsLen int
		read  int
		err   error
	)
	bsLen = len(bs)
	read, err = rand.Read(bs)
	if err != nil {
		return err
	}
	if read != bsLen {
		return ErrInsufficientEntropy
	}
	return nil
}
