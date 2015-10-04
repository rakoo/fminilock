package minilock

import (
	"encoding/base64"
	"encoding/json"
	"github.com/cathalgarvey/go-minilock/taber"
	"github.com/dchest/blake2s"
)

// Encrypt a file symmetrically and return a FileInfo object for it.
func EncryptFileToFileInfo(filename string, filecontents []byte) (FI *FileInfo, ciphertext []byte, err error) {
	// taber.Encrypt(filename string, file_data []byte) (DI *DecryptInfo, ciphertext []byte, err error)
	var (
		DI *taber.DecryptInfo
	)
	DI, err = taber.NewDecryptInfo()
	if err != nil {
		return nil, nil, err
	}
	return encryptFileToFileInfo(DI, filename, filecontents)
}

// Separated from the above for testing purposes; deterministic ciphertext.
func encryptFileToFileInfo(DI *taber.DecryptInfo, filename string, filecontents []byte) (FI *FileInfo, ciphertext []byte, err error) {
	var hash [32]byte
	ciphertext, err = DI.Encrypt(filename, filecontents)
	if err != nil {
		return nil, nil, err
	}
	hash = blake2s.Sum256(ciphertext)
	FI = new(FileInfo)
	FI.FileKey = DI.Key
	FI.FileNonce = DI.BaseNonce
	FI.FileHash = hash[:]
	return FI, ciphertext, nil
}

func NewDecryptInfoEntry(nonce []byte, fileinfo *FileInfo, senderKey, recipientKey *taber.Keys) (*DecryptInfoEntry, error) {
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
func EncryptDecryptInfo(di *DecryptInfoEntry, nonce []byte, ephemKey, recipientKey *taber.Keys) ([]byte, error) {
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

func (self *miniLockv1Header) addFileInfo(fileInfo *FileInfo, ephem, sender *taber.Keys, recipients ...*taber.Keys) error {
	for _, recipientKey := range recipients {
		nonce, rgerr := makeFullNonce()
		if rgerr != nil {
			return rgerr
		}
		// NewDecryptInfoEntry(nonce []byte, fileinfo *FileInfo, senderKey, recipientKey *taber.Keys) (*DecryptInfoEntry, error) {
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

// This is an entry point that largely defines "normal" miniLock behaviour.
// If sendToSender is true, then the sender's ID is added to recipients.
func EncryptFileContentsWithStrings(filename string, fileContents []byte, senderEmail, senderPassphrase string, sendToSender bool, recipientIDs... string)  (miniLockContents []byte, err error){
    var (
			senderKey, this_recipient *taber.Keys
			recipientKeyList []*taber.Keys
			this_id string
		)
		senderKey, err = taber.FromEmailAndPassphrase(senderEmail, senderPassphrase)
		if err != nil {
			return nil, err
		}
		if sendToSender {
			this_id, err = senderKey.EncodeID()
			if err != nil {
				return nil, err
			}
		}
    recipientKeyList = make([]*taber.Keys, 0, len(recipientIDs))
    // TODO: Randomise iteration here?
		for _, this_id = range recipientIDs {
			this_recipient, err = taber.FromID(this_id)
			if err != nil {
				return nil, err
			}
			recipientKeyList = append(recipientKeyList, this_recipient)
		}
		miniLockContents, err = EncryptFileContents(filename, fileContents, senderKey, recipientKeyList...)
		if err != nil {
			return nil, err
		}
		return miniLockContents, nil
}

func EncryptFileContents(filename string, fileContents []byte, sender *taber.Keys, recipients... *taber.Keys) (miniLockContents []byte, err error) {
	var (
		hdr        *miniLockv1Header
		ephem      *taber.Keys
		ciphertext []byte
		fileInfo   *FileInfo
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
	miniLockContents = make([]byte, 0, 8+4+hdr.encodedLength()+len(ciphertext))
	miniLockContents, err = hdr.stuffSelf(miniLockContents)
	if err != nil {
		return nil, err
	}
	miniLockContents = append(miniLockContents, ciphertext...)
	return miniLockContents, nil
}
