package minilock

import "errors"

var (
	MagicBytesError          = errors.New("Magic bytes didn't match expected 'miniLock'.")
	BadLengthPrefixError     = errors.New("Header length exceeds file length.")
	CTHashMismatchError      = errors.New("Ciphertext hash did not match.")
	BadRecipientError        = errors.New("DecryptInfo successfully decrypted but was addressed to another key! (WTF?)")
	CannotDecryptError       = errors.New("Could not decrypt given ciphertext with given key or nonce.")
	NotEnoughRandomnessError = errors.New("Got insufficient random bytes from RNG.")
)
