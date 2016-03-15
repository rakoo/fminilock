package taber

import "errors"

var (
	ErrBadKeyLength       = errors.New("Encryption key must be 32 bytes long.")
	ErrBadBaseNonceLength = errors.New("Length of base_nonce must be 16.")
	ErrBadLengthPrefix    = errors.New("Block length prefixes indicate a length longer than the remaining ciphertext.")
	ErrBadPrefix          = errors.New("Chunk length prefix is longer than 4 bytes, would clobber ciphertext.")
	ErrBadBoxAuth         = errors.New("Authentication of box failed on opening.")
	ErrBadBoxDecryptVars  = errors.New("Key or Nonce is not correct length to attempt decryption.")
	ErrBoxDecryptionEOP   = errors.New("Declared length of chunk would write past end of plaintext slice!")
	ErrBoxDecryptionEOS   = errors.New("Chunk length is longer than expected slot in plaintext slice.")
	ErrFilenameTooLong    = errors.New("Filename cannot be longer than 256 bytes.")
	ErrNilPlaintext       = errors.New("Asked to encrypt empty plaintext.")
)
