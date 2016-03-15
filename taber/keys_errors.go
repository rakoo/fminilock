package taber

import "errors"

var (
	ErrChecksumFail        = errors.New("Generating checksum value failed")
	ErrInsufficientEntropy = errors.New("Got insufficient random bytes from RNG")
	ErrInvalidIDLength     = errors.New("Provided public ID was not expected length (33 bytes when decoded)")
	ErrInvalidIDChecksum   = errors.New("Provided public ID had an invalid checksum")
	ErrPrivateKeyOpOnly    = errors.New("Cannot conduct specified operation using a public-only keypair")
	ErrBadNonceLength      = errors.New("Nonce length must be 24 length")
	ErrDecryptionAuthFail  = errors.New("Authentication of decryption using keys failed")
)
