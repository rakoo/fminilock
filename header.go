package minilock

import (
	"encoding/json"
	"github.com/cathalgarvey/go-minilock/taber"
)

// This is the marrow at the heart of the miniLock header that contains
// decryption instructions for the encrypted file container.
type FileInfo struct {
	FileKey   []byte `json:"fileKey"`
	FileNonce []byte `json:"fileNonce"`
	FileHash  []byte `json:"fileHash"`
}

// This is the container for the decryption instructions of "FileInfo",
// also containing sender and recipient. It is encrypted to the recipient
// with an ephemeral key to preserve privacy.
type DecryptInfoEntry struct {
	SenderID    string `json:"senderID"`
	RecipientID string `json:"recipientID"`
	FileInfoEnc []byte `json:"fileInfo"`
}

func (self *DecryptInfoEntry) SenderPubkey() (*taber.Keys, error) {
	return taber.FromID(self.SenderID)
}

// This is the header that goes atop a miniLock file after the magic
// bytes. It contains an ephemeral key and a map of recipient "DecryptInfo"
// objects, which are encrypted to the recipients with the ephmeral Key
// to preserve privacy. The recipient(s) must iterate through these with their
// keys until they unlock one successfully; there is no indication at this
// level who the sender or recipients are, by design.
type miniLockv1Header struct {
	Version     int               `json:"version"`
	Ephemeral   []byte            `json:"ephemeral"`
	DecryptInfo map[string][]byte `json:"decryptInfo"`
}

// Keygens a new ephemeral key, returns the header plus this key.
func prepareNewHeader() (*miniLockv1Header, *taber.Keys, error) {
	hdr := new(miniLockv1Header)
	hdr.Version = 1
	ephem, err := taber.RandomKey()
	if err != nil {
		return nil, nil, err
	}
	hdr.Ephemeral = ephem.Public
	hdr.DecryptInfo = make(map[string][]byte)
	return hdr, ephem, nil
}

// Header data is pretty constant, so should be possible to predict length based
// on number of entries in DecryptInfo map!
// URGENT TODO: Refactor to do things intelligently, this is just a placeholder.
func (self *miniLockv1Header) encodedLength() int {
	// Get minified JSON header and length.
	enc_header, err := json.Marshal(self)
	if err != nil {
		return 0
	}
	return len(enc_header)
}

// Encode 'miniLock<int32 LE header length prefix><header JSON>' into "into",
// return "into" (in case of reallocations)
func (self *miniLockv1Header) stuffSelf(into []byte) ([]byte, error) {
	// Get minified JSON header and length.
	enc_header, err := json.Marshal(self)
	if err != nil {
		return nil, err
	}
	hdrLength := len(enc_header)
	hdrLengthLE, err := toLittleEndian(int32(hdrLength))
	if err != nil {
		return nil, err
	}
	into = append(into, []byte("miniLock")...)
	into = append(into, hdrLengthLE...)
	into = append(into, enc_header...)
	return into, nil
}
