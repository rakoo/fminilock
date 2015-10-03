package taber

import "errors"

var (
	WrongLengthKeyError         = errors.New("Encryption key must be 32 bytes long.")
	BadBaseNonceError           = errors.New("Length of base_nonce must be 16.")
	BadLengthPrefixError        = errors.New("Block length prefixes indicate a length longer than the remaining ciphertext.")
	BadGeneratedPrefixError     = errors.New("Chunk length prefix is longer than 4 bytes, would clobber ciphertext.")
	BoxAuthenticationError      = errors.New("Authentication of box failed on opening.")
	BoxDecryptionVariablesError = errors.New("Key or Nonce is not correct length to attempt decryption.")
	BoxDecryptionEOPError       = errors.New("Declared length of chunk would write past end of plaintext slice!")
	BoxDecryptionEOSError       = errors.New("Chunk length is longer than expected slot in plaintext slice.")
	FilenameTooLongError        = errors.New("Filename cannot be longer than 256 bytes.")
	NotEnoughRandomnessError    = errors.New("Got insufficient random bytes from RNG.")
)
