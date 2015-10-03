package taber

import "errors"

var (
	ChecksumGenerationError      = errors.New("Generating checksum value failed..")
	EntropyInconsistencyError    = errors.New("Asked for 32 bytes of rand.Reader but got some other number!")
	InvalidIDLengthError         = errors.New("Provided public ID was not expected length (33 bytes when decoded).")
	InvalidIDChecksumError       = errors.New("Provided public ID had an invalid checksum.")
	PrivateKeyOnlyOperationError = errors.New("Cannot conduct specified operation using a public-only keypair.")
	NonceLengthError             = errors.New("Nonce length must be 24 length.")
	KeyDecryptionError           = errors.New("Authentication of decryption using keys failed.")
)
