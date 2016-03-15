package minilock

import "errors"

var (
	ErrBadMagicBytes       = errors.New("Magic bytes didn't match expected 'miniLock'.")
	ErrBadLengthPrefix     = errors.New("Header length exceeds file length.")
	ErrCTHashMismatch      = errors.New("Ciphertext hash did not match.")
	ErrBadRecipient        = errors.New("DecryptInfo successfully decrypted but was addressed to another key! (WTF?)")
	ErrCannotDecrypt       = errors.New("Could not decrypt given ciphertext with given key or nonce.")
	ErrInsufficientEntropy = errors.New("Got insufficient random bytes from RNG.")
	ErrNilPlaintext        = errors.New("Got empty plaintext, can't encrypt")
)
