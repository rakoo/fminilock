package minilockkeys

import (
  "github.com/cathalgarvey/go-minilock/minilockutils"
  "golang.org/x/crypto/nacl/box"
)

func nonceToArray(nonce []byte) *[24]byte {
  arr := new([24]byte)
  copy(arr[:], nonce)
  return arr
}

func (self *NaClKeypair) Encrypt(plaintext, nonce []byte, to *NaClKeypair) (ciphertext []byte, err error) {
  if len(nonce) != 24 {
    return nil, minilockutils.BadArgumentError("Nonce must be 24 bytes long.")
  }
  ciphertext = make([]byte, 0, len(plaintext) + box.Overhead)
  ciphertext = box.Seal(ciphertext, plaintext, nonceToArray(nonce), to.PublicArray(), self.PrivateArray())
  return ciphertext, nil
}

func (self *NaClKeypair) Decrypt(ciphertext, nonce []byte, from *NaClKeypair) (plaintext []byte, err error) {
  var ok bool
  if len(nonce) != 24 {
    return nil, minilockutils.BadArgumentError("Nonce must be 24 bytes long.")
  }
  plaintext = make([]byte, 0, len(ciphertext) - box.Overhead)
  plaintext, ok = box.Open(plaintext[:], ciphertext, nonceToArray(nonce), from.PublicArray(), self.PrivateArray())
  if !ok {
    return nil, minilockutils.AuthenticationError("Authentication Failed!")
  }
  return plaintext, nil
}
