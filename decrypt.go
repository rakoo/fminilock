package minilock

import (
	"encoding/json"
	"github.com/cathalgarvey/go-minilock/minilockkeys"
	"github.com/cathalgarvey/go-minilock/minilockutils"
	"io/ioutil"
)

const magicBytes = "miniLock"

// Opens file and passes to ParseFileContents
func ParseFile(filepath string) (header *miniLockv1Header, ciphertext []byte, err error) {
	fc, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, nil, err
	}
	return ParseFileContents(fc)
}

func ParseFileContents(contents []byte) (header *miniLockv1Header, ciphertext []byte, err error) {
	magic := string(contents[:8])
	if magic != magicBytes {
		return nil, nil, minilockutils.BadEncodingError("miniLock magic bytes not found; are you sure this is a miniLock file?")
	}
	header_length_i32, err := minilockutils.FromLittleEndian(contents[8:12])
	if err != nil {
		return nil, nil, err
	}
	header_length := int(header_length_i32)
	if 12+header_length > len(contents) {
		return nil, nil, minilockutils.BadEncodingError("Header length exceeds file length")
	}
	header_bytes := contents[12 : 12+header_length]
	ciphertext = contents[12+header_length:]
	header = new(miniLockv1Header)
	err = json.Unmarshal(header_bytes, header)
	if err != nil {
		return nil, nil, err
	}
	return header, ciphertext, nil
}

func DecryptFileContents(file_contents []byte, recipientKey *minilockkeys.NaClKeypair) (senderID, filename string, contents []byte, err error) {
	var (
		header     *miniLockv1Header
		ciphertext []byte
	)
	header, ciphertext, err = ParseFileContents(file_contents)
	if err != nil {
		return "", "", nil, err
	}
	return header.DecryptContents(ciphertext, recipientKey)
}
