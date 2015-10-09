package minilock

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/cathalgarvey/go-minilock/taber"
	"github.com/dchest/blake2s"
	"io/ioutil"
)

// Opens file and passes to ParseFileContents
func ParseFile(filepath string) (header *miniLockv1Header, ciphertext []byte, err error) {
	fc, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, nil, err
	}
	return ParseFileContents(fc)
}

// Parses a miniLock file and returns header and ciphertext.
func ParseFileContents(contents []byte) (header *miniLockv1Header, ciphertext []byte, err error) {
	var (
		header_length_i32 int32
		header_length     int
		header_bytes      []byte
	)
	if string(contents[:8]) != magicBytes {
		return nil, nil, MagicBytesError
	}
	header_length_i32, err = fromLittleEndian(contents[8:12])
	if err != nil {
		return nil, nil, err
	}
	header_length = int(header_length_i32)
	if 12+header_length > len(contents) {
		return nil, nil, BadLengthPrefixError
	}
	header_bytes = contents[12 : 12+header_length]
	ciphertext = contents[12+header_length:]
	header = new(miniLockv1Header)
	err = json.Unmarshal(header_bytes, header)
	if err != nil {
		return nil, nil, err
	}
	return header, ciphertext, nil
}

// Parse header and ciphertext from a file, decrypt the header with recipientKey,
// and use details therein to decrypt the enclosed file. Returns sender, filename,
// file contents if successful, or an error if not; Check the error to see if it's
// benign (cannot decrypt with given key) or bad.
func DecryptFileContents(file_contents []byte, recipientKey *taber.Keys) (senderID, filename string, contents []byte, err error) {
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

// Given a ciphertext, walk it into length prefixed chunks and decrypt/reassemble
// each chunk, then validate the hash of the file against the hash given in FileInfo.
// The result is a validated, decrypted filename and file contents byte-slice.
func (self *FileInfo) DecryptFile(ciphertext []byte) (filename string, contents []byte, err error) {
	var (
		hash [32]byte
		DI   taber.DecryptInfo
	)
	hash = blake2s.Sum256(ciphertext)
	if !bytes.Equal(self.FileHash, hash[:]) {
		return "", nil, CTHashMismatchError
	}
	DI = taber.DecryptInfo{Key: self.FileKey, BaseNonce: self.FileNonce}
	return DI.Decrypt(ciphertext)
}

func DecryptDecryptInfo(di_enc, nonce []byte, ephemPubkey, recipientKey *taber.Keys) (*DecryptInfoEntry, error) {
	plain, err := recipientKey.Decrypt(di_enc, nonce, ephemPubkey)
	if err != nil {
		return nil, CannotDecryptError
	}
	di := new(DecryptInfoEntry)
	err = json.Unmarshal(plain, di)
	if err != nil {
		return nil, err
	}
	return di, nil
}

func (self *DecryptInfoEntry) ExtractFileInfo(nonce []byte, recipientKey *taber.Keys) (*FileInfo, error) {
	// Return on failure: minilockutils.DecryptionError
	senderPubkey, err := self.SenderPubkey()
	if err != nil {
		return nil, err
	}
	plain, err := recipientKey.Decrypt(self.FileInfoEnc, nonce, senderPubkey)
	if err != nil {
		return nil, CannotDecryptError
	}
	fi := new(FileInfo)
	err = json.Unmarshal(plain, fi)
	if err != nil {
		return nil, err
	}
	return fi, nil
}

// Iterates through the header using recipientKey and attempts to decrypt any
// DecryptInfoEntry using the provided ephemeral key.
// If unsuccessful, returns minilockutils.DecryptionError
func (self *miniLockv1Header) ExtractDecryptInfo(recipientKey *taber.Keys) (nonce []byte, DI *DecryptInfoEntry, err error) {
	var (
		ephem_key *taber.Keys
		enc_DI    []byte
		nonce_s   string
	)
	ephem_key = new(taber.Keys)
	ephem_key.Public = self.Ephemeral
	if err != nil {
		return nil, nil, err
	}
	// Look for a DI we can decrypt with recipientKey
	// TODO: Make this concurrent!
	for nonce_s, enc_DI = range self.DecryptInfo {
		nonce, err := base64.StdEncoding.DecodeString(nonce_s)
		if err != nil {
			return nil, nil, err
		}
		DI, err = DecryptDecryptInfo(enc_DI, nonce, ephem_key, recipientKey)
		if err == CannotDecryptError {
			continue
		} else if err != nil {
			return nil, nil, err
		}
		recipID, err := recipientKey.EncodeID()
		if err != nil {
			return nil, nil, err
		}
		if DI.RecipientID != recipID {
			return nil, nil, BadRecipientError
		}
		return nonce, DI, nil
	}
	return nil, nil, CannotDecryptError
}

func (self *miniLockv1Header) ExtractFileInfo(recipientKey *taber.Keys) (fileinfo *FileInfo, senderID string, err error) {
	nonce, DI, err := self.ExtractDecryptInfo(recipientKey)
	if err != nil {
		return nil, "", err
	}
	fileinfo, err = DI.ExtractFileInfo(nonce, recipientKey)
	if err != nil {
		return nil, "", err
	}
	return fileinfo, DI.SenderID, nil
}

func (self *miniLockv1Header) DecryptContents(ciphertext []byte, recipientKey *taber.Keys) (senderID, filename string, contents []byte, err error) {
	var FI *FileInfo
	FI, senderID, err = self.ExtractFileInfo(recipientKey)
	if err != nil {
		return "", "", nil, err
	}
	filename, contents, err = FI.DecryptFile(ciphertext)
	if err != nil {
		return "", "", nil, err
	}
	return senderID, filename, contents, nil
}
