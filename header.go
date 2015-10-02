package minilock

import (
  //"bytes"
  //"fmt"
  "encoding/json"
  "encoding/base64"
  "github.com/dchest/blake2s"
  "github.com/cathalgarvey/go-minilock/minilockkeys"
  "github.com/cathalgarvey/go-minilock/minilockbox"
  "github.com/cathalgarvey/go-minilock/minilockutils"
)

var CannotDecrypt = minilockutils.DecryptionError("Could not decrypt given ciphertext with given key or nonce.")

type FileInfo struct{
  FileKey []byte `json:"fileKey"`
  FileNonce []byte `json:"fileNonce"`
  FileHash []byte `json:"fileHash"`
}

// Encrypt a file symmetrically and return a FileInfo object for it.
func EncryptFileToFileInfo(filename string, filecontents []byte) (FI *FileInfo, ciphertext []byte, err error) {
  var (
    key, nonce []byte
  )
  key, err = minilockutils.MakeSymmetricKey()
  if err != nil {
    return nil, nil, err
  }
  nonce, err = minilockutils.MakeBaseNonce()
  if err != nil {
    return nil, nil, err
  }
  return encryptFileToFileInfo(nonce, key, filename, filecontents)
}

// Separated from the above for testing purposes; deterministic ciphertext.
func encryptFileToFileInfo(nonce, key []byte, filename string, filecontents []byte) (FI *FileInfo, ciphertext []byte, err error) {
// minilockbox.Encrypt(filename string, key, base_nonce, file_data []byte) (ciphertext []byte, err error)
  var hash [32]byte
  ciphertext, err = minilockbox.Encrypt(filename, key, nonce, filecontents)
  if err != nil {
    return nil, nil, err
  }
  hash = blake2s.Sum256(ciphertext)
  return &FileInfo{FileKey: key, FileNonce: nonce, FileHash: hash[:]}, ciphertext, nil
}

// Given a ciphertext, walk it into length prefixed chunks and decrypt/reassemble
// each chunk, then validate the hash of the file against the hash given in FileInfo.
// The result is a validated, decrypted filename and file contents byte-slice.
func (self *FileInfo) DecryptFile(ciphertext []byte) (filename string, contents []byte, err error) {
  // minilockbox.Decrypt(key, base_nonce, ciphertext []byte) (filename string, plaintext []byte, err error)
  hash := blake2s.Sum256(ciphertext)
  if !minilockutils.CmpSlices(self.FileHash, hash[:]) {
    return "", nil, minilockutils.AuthenticationError("File hash did not match!")
  }
  filename, contents, err = minilockbox.Decrypt(self.FileKey, self.FileNonce, ciphertext)
  if err != nil {
    return "", nil, err
  }
  return filename, contents, nil
}

type DecryptInfoEntry struct{
  SenderID string `json:"senderID"`
  RecipientID string `json:"recipientID"`
  FileInfoEnc []byte `json:"fileInfo"`
}

func NewDecryptInfoEntry(nonce []byte, fileinfo *FileInfo, senderKey, recipientKey *minilockkeys.NaClKeypair) (*DecryptInfoEntry, error) {
  encoded_fi, err := json.Marshal(fileinfo)
  if err != nil {
    return nil, err
  }
  cipher_fi, err := senderKey.Encrypt(encoded_fi, nonce, recipientKey)
  if err != nil {
    return nil, err
  }
  senderID, err := senderKey.EncodeID()
  if err != nil {
    return nil, err
  }
  recipientID, err := recipientKey.EncodeID()
  if err != nil {
    return nil, err
  }
  return &DecryptInfoEntry{SenderID: senderID, RecipientID: recipientID, FileInfoEnc: cipher_fi}, nil
}

// Encrypt a decryptInfo struct using the ephemeral pubkey and the same nonce as the enclosed fileInfo.
func EncryptDecryptInfo(di *DecryptInfoEntry, nonce []byte, ephemKey, recipientKey *minilockkeys.NaClKeypair) ([]byte, error) {
  plain, err := json.Marshal(di)
  if err != nil {
    return nil, err
  }
  // NaClKeypair.Encrypt(plaintext, nonce []byte, to *NaClKeypair) (ciphertext []byte, err error)
  di_enc, err := ephemKey.Encrypt(plain, nonce, recipientKey)
  if err != nil {
    return nil, err
  }
  return di_enc, nil
}

func DecryptDecryptInfo(di_enc, nonce []byte, ephemPubkey, recipientKey *minilockkeys.NaClKeypair) (*DecryptInfoEntry, error) {
  plain, err := recipientKey.Decrypt(di_enc, nonce, ephemPubkey)
  if err != nil {
    return nil,  CannotDecrypt
  }
  di := new(DecryptInfoEntry)
  err = json.Unmarshal(plain, di)
  if err != nil {
    return nil, err
  }
  return di, nil
}

func (self *DecryptInfoEntry) SenderPubkey() (*minilockkeys.NaClKeypair, error) {
  return minilockkeys.FromID(self.SenderID)
}

func (self *DecryptInfoEntry) ExtractFileInfo(nonce []byte, recipientKey *minilockkeys.NaClKeypair) (*FileInfo, error) {
  // Return on failure: minilockutils.DecryptionError
  senderPubkey, err := self.SenderPubkey()
  if err != nil {
    return nil, err
  }
  plain, err := recipientKey.Decrypt(self.FileInfoEnc, nonce, senderPubkey)
  if err != nil {
    return nil, CannotDecrypt
  }
  fi := new(FileInfo)
  err = json.Unmarshal(plain, fi)
  if err != nil {
    return nil, err
  }
  return fi, nil
}

type miniLockv1Header struct {
  Version int `json:"version"`
  Ephemeral []byte `json:"ephemeral"`
  DecryptInfo map[string][]byte `json:"decryptInfo"`
}

// Iterates through the header using recipientKey and attempts to decrypt any
// DecryptInfoEntry using the provided ephemeral key.
// If unsuccessful, returns minilockutils.DecryptionError
func (self *miniLockv1Header) ExtractDecryptInfo(recipientKey *minilockkeys.NaClKeypair) (nonce []byte, DI *DecryptInfoEntry, err error) {
  var (
    ephem_key *minilockkeys.NaClKeypair
    enc_DI []byte
    nonce_s string
  )
  ephem_key = new(minilockkeys.NaClKeypair)
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
    DI, err = DecryptDecryptInfo(enc_DI, nonce,  ephem_key, recipientKey)
    if err == CannotDecrypt {
      continue
    } else if err != nil {
      return nil, nil, err
    }
    recipID, err := recipientKey.EncodeID()
    if err != nil {
      return nil, nil, err
    }
    if DI.RecipientID != recipID {
      return nil, nil, minilockutils.DecryptionError("DecryptInfo successfully decrypted but was addressed to another key! (WTF?)")
    }
    return nonce, DI, nil
  }
  return nil, nil, CannotDecrypt
}

func (self *miniLockv1Header) ExtractFileInfo(recipientKey *minilockkeys.NaClKeypair) (fileinfo *FileInfo, senderID string, err error) {
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

func (self *miniLockv1Header) DecryptContents(ciphertext []byte, recipientKey *minilockkeys.NaClKeypair) (senderID, filename string, contents []byte, err error) {
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

// Keygens a new ephemeral key, returns the header plus this key.
func prepareNewHeader() (*miniLockv1Header, *minilockkeys.NaClKeypair, error) {
  hdr := new(miniLockv1Header)
  hdr.Version = 1
  ephem, err := minilockkeys.Ephemeral()
  if err != nil {
    return nil, nil, err
  }
  hdr.Ephemeral = ephem.Public
  hdr.DecryptInfo = make(map[string][]byte)
  return hdr, ephem, nil
}

func (self *miniLockv1Header) addFileInfo(fileInfo *FileInfo, ephem, sender *minilockkeys.NaClKeypair, recipients... *minilockkeys.NaClKeypair) error {
  for _, recipientKey := range recipients {
    nonce, rgerr := minilockutils.MakeFullNonce()
    if rgerr != nil {
      return rgerr
    }
    // NewDecryptInfoEntry(nonce []byte, fileinfo *FileInfo, senderKey, recipientKey *minilockkeys.NaClKeypair) (*DecryptInfoEntry, error) {
    DI, rgerr := NewDecryptInfoEntry(nonce, fileInfo, sender, recipientKey)
    if rgerr != nil {
      return rgerr
    }
    enc_DI, rgerr := EncryptDecryptInfo(DI, nonce, ephem, recipientKey)
    if rgerr != nil {
      return rgerr
    }
    nonce_s := base64.StdEncoding.EncodeToString(nonce)
    self.DecryptInfo[nonce_s] = enc_DI
  }
  return nil
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
  hdrLengthLE, err := minilockutils.ToLittleEndian(int32(hdrLength))
  if err != nil {
    return nil, err
  }
  into = append(into, []byte("miniLock")...)
  into = append(into, hdrLengthLE...)
  into = append(into, enc_header...)
  return into, nil
}

func EncryptFile(filename string, fileContents []byte, sender *minilockkeys.NaClKeypair, recipients... *minilockkeys.NaClKeypair) (miniLockContents []byte, err error) {
  var (
    hdr *miniLockv1Header
    ephem *minilockkeys.NaClKeypair
    ciphertext []byte
    fileInfo *FileInfo
  )
  hdr, ephem, err = prepareNewHeader()
  if err != nil {
    return nil, err
  }
  fileInfo, ciphertext, err = EncryptFileToFileInfo(filename, fileContents)
  if err != nil {
    return nil, err
  }
  err = hdr.addFileInfo(fileInfo, ephem, sender, recipients...)
  if err != nil {
    return nil, err
  }
  miniLockContents = make([]byte, 0, 8 + 4 + hdr.encodedLength() + len(ciphertext))
  miniLockContents, err = hdr.stuffSelf( miniLockContents )
  if err != nil {
    return nil, err
  }
  miniLockContents = append(miniLockContents, ciphertext...)
  return miniLockContents, nil
}
