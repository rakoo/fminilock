package taber

import (
	"golang.org/x/crypto/nacl/box"
)

func (self *Keys) Encrypt(plaintext, nonce []byte, to *Keys) (ciphertext []byte, err error) {
	if len(nonce) != 24 {
		return nil, NonceLengthError
	}
	ciphertext = make([]byte, 0, len(plaintext)+box.Overhead)
	ciphertext = box.Seal(ciphertext, plaintext, nonceToArray(nonce), to.PublicArray(), self.PrivateArray())
	return ciphertext, nil
}

func (self *Keys) Decrypt(ciphertext, nonce []byte, from *Keys) (plaintext []byte, err error) {
	var ok bool
	if len(nonce) != 24 {
		return nil, NonceLengthError
	}
	plaintext = make([]byte, 0, len(ciphertext)-box.Overhead)
	plaintext, ok = box.Open(plaintext[:], ciphertext, nonceToArray(nonce), from.PublicArray(), self.PrivateArray())
	if !ok {
		return nil, KeyDecryptionError
	}
	return plaintext, nil
}
