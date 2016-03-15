package taber

import (
	"bytes"
	"crypto/rand"
	"github.com/cathalgarvey/base58"
	"github.com/dchest/blake2s"
	"golang.org/x/crypto/nacl/box"
)

// Taber NaCl keys are stored simply as two byte slices with handy methods attached.
// They can be generated determnistically from passphrase and email, according
// to the method used by miniLock.io, or randomly generated. They can emit
// an "ID" as a string, which is the base58 representation of the public Key
// with a one-byte checksum, and can be imported from same.
// They have a "Wipe" method which should always be used when finished with the
// keys to protect keys from compromise.
type Keys struct {
	// May be empty for pubkey-only keypairs.
	Private []byte

	// Should always be full.
	Public []byte
}

// Merely verifies whether a byte slice is 32 bytes long.
func (self *Keys) mayBeAKey(part []byte) bool {
	if part != nil && len(part) == 32 {
		return true
	} else {
		return false
	}
}

func (self *Keys) HasPublic() bool {
	return self.mayBeAKey(self.Public)
}

func (self *Keys) HasPrivate() bool {
	return self.mayBeAKey(self.Private)
}

// Some nacl functions require arrays, not slices. Note; the returned array is a copy.
func (self *Keys) PrivateArray() *[32]byte {
	if !self.HasPrivate() {
		return nil
	}
	arr := new([32]byte)
	copy(arr[:], self.Private)
	return arr
}

// Some nacl functions require arrays, not slices. Note; the returned array is a copy.
func (self *Keys) PublicArray() *[32]byte {
	arr := new([32]byte)
	copy(arr[:], self.Public)
	return arr
}

// Returns a Keys object containing only the public key of this object.
func (self *Keys) PublicOnly() *Keys {
	PK := new(Keys)
	PK.Public = make([]byte, len(self.Public))
	copy(PK.Public, self.Public)
	return PK
}

// Generate a fully random Keys struct from a secure random source.
func RandomKey() (*Keys, error) {
	rand_bytes := make([]byte, 32)
	read, err := rand.Read(rand_bytes)
	if err != nil {
		return nil, err
	}
	if read != 32 {
		return nil, ErrInsufficientEntropy
	}
	rand_reader := bytes.NewReader(rand_bytes)
	public, private, err := box.GenerateKey(rand_reader)
	if err != nil {
		return nil, err
	}
	// Always be explicit about public/private material in case struct is
	// rearranged (/accidentally) later on
	return &Keys{Private: private[:], Public: public[:]}, nil
}

// Generate keys using a passphrase using an email as salt value.
// The passphrase is first hashed using 32-byte blake2s and is then
// passed through scrypt using the email as salt. 32 bytes of scrypt
// output are used to create a private nacl.box key and a keys object.
func FromEmailAndPassphrase(email, passphrase string) (*Keys, error) {
	pp_scrypt, err := Harden(email, passphrase)
	if err != nil {
		return nil, err
	}
	scrypt_Reader := bytes.NewReader(pp_scrypt)
	public, private, err := box.GenerateKey(scrypt_Reader)
	if err != nil {
		return nil, err
	}
	// Always be explicit about public/private material in case struct is
	// rearranged (/accidentally) later on
	return &Keys{Private: private[:], Public: public[:]}, nil
}

// Import a public-only Keys struct from an ID string, using the last byte as
// a blake2s checksum.
func FromID(id string) (*Keys, error) {
	key_cs_buf, err := base58.StdEncoding.Decode([]byte(id))
	if err != nil {
		return nil, err
	}
	if len(key_cs_buf) != 33 {
		return nil, ErrInvalidIDLength
	}
	kp := Keys{Public: key_cs_buf[:len(key_cs_buf)-1]}
	cs := key_cs_buf[len(key_cs_buf)-1:]
	// TODO: Is constant time important here at all?
	// cs_2 is guaranteed length 1 here or err will be a BadProgrammingError.
	cs_2, err := kp.checksum()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(cs, cs_2) {
		if err != nil {
			return nil, err
		} else {
			return nil, ErrInvalidIDChecksum
		}
	}
	return &kp, nil
}

// Generate 1-byte checksum using blake2s.
func (self *Keys) checksum() ([]byte, error) {
	var written int
	blakeHasher, err := blake2s.New(&blake2s.Config{Size: 1})
	if err != nil {
		return nil, err
	}
	written, err = blakeHasher.Write(self.Public)
	if err != nil {
		return nil, err
	}
	if written != 32 {
		return nil, ErrChecksumFail
	}
	checksum := blakeHasher.Sum(nil)
	if len(checksum) != 1 {
		return nil, ErrChecksumFail
	}
	return checksum, nil
}

// Generate base58-encoded pubkey + 1-byte blake2s checksum as a string.
func (self *Keys) EncodeID() (string, error) {
	plen := len(self.Public)
	idbuf := make([]byte, plen, plen+1)
	copy(idbuf, self.Public)
	cs, err := self.checksum()
	if err != nil {
		return "", err
	}
	idbuf = append(idbuf, cs[0])
	id := base58.StdEncoding.Encode(idbuf)
	return string(id), nil
}

// Overwrite memory containing key material; calling this method when
// finished with a key is strongly advised to prevent compromise.
func (self *Keys) Wipe() error {
	var (
		read int
		err  error
	)
	if self.HasPrivate() {
		read, err = rand.Read(self.Private)
		if err != nil {
			return err
		}
		if read != 32 {
			return ErrInsufficientEntropy
		}
	}
	read, err = rand.Read(self.Public)
	if err != nil {
		return err
	}
	if read != 32 {
		return ErrInsufficientEntropy
	}
	return nil
}
