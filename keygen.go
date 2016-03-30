package minilock

import (
	"bytes"

	"github.com/agl/ed25519"
	"github.com/cathalgarvey/base58"
	"github.com/cathalgarvey/go-minilock/taber"
	"github.com/dchest/blake2s"
)

// GenerateKey makes a key from an email address and passphrase, consistent
// with the miniLock algorithm. Passphrase is *not* currently checked
// for strength so it is, at present, the caller's responsibility to
// provide passphrases that don't suck!
func GenerateKey(email string, passphrase string) (*taber.Keys, error) {
	return taber.FromEmailAndPassphrase(email, passphrase)
}

// EphemeralKey generates a fully random key, usually for ephemeral uses.
func EphemeralKey() (*taber.Keys, error) {
	return taber.RandomKey()
}

// ImportID imports a miniLock ID as a public key.
func ImportID(id string) (*taber.Keys, error) {
	return taber.FromID(id)
}

// LoadKey manually loads a key from public and private binary strings.
func LoadKey(private, public []byte) *taber.Keys {
	return &taber.Keys{Private: private, Public: public}
}

// Encodable is an interface for a key that can encode itself into a
// string representation
type Encodable interface {
	EncodeID() (string, error)
}

type IdentityKeys struct {
	Private []byte
	Public  []byte
}

func IdentityFromEmailAndPassphrase(guid, passphrase string) (*IdentityKeys, error) {
	ppScrypt, err := taber.Harden(guid, passphrase)
	if err != nil {
		return nil, err
	}
	scryptReader := bytes.NewReader(ppScrypt)
	public, private, err := ed25519.GenerateKey(scryptReader)
	if err != nil {
		return nil, err
	}
	return &IdentityKeys{Private: private[:], Public: public[:]}, nil
}

// EncodeID generate base58-encoded pubkey + 1-byte blake2s checksum as a string.
func (iks *IdentityKeys) EncodeID() (string, error) {
	plen := len(iks.Public)
	idbuf := make([]byte, plen, plen+1)
	copy(idbuf, iks.Public)
	cs, err := iks.checksum()
	if err != nil {
		return "", err
	}
	idbuf = append(idbuf, cs[0])
	id := base58.StdEncoding.Encode(idbuf)
	return string(id), nil
}

// Generate 1-byte checksum using blake2s.
func (iks *IdentityKeys) checksum() ([]byte, error) {
	var written int
	blakeHasher, err := blake2s.New(&blake2s.Config{Size: 1})
	if err != nil {
		return nil, err
	}
	written, err = blakeHasher.Write(iks.Public)
	if err != nil {
		return nil, err
	}
	if written != 32 {
		return nil, taber.ErrChecksumFail
	}
	checksum := blakeHasher.Sum(nil)
	if len(checksum) != 1 {
		return nil, taber.ErrChecksumFail
	}
	return checksum, nil
}

func (iks *IdentityKeys) Sign(content []byte) []byte {
	var pk [ed25519.PrivateKeySize]byte
	copy(pk[:], iks.Private)
	signature := ed25519.Sign(&pk, content)
	return signature[:]
}

func IdentityFromID(ID string) (*IdentityKeys, error) {
	keyCSbuf, err := base58.StdEncoding.Decode([]byte(ID))
	if err != nil {
		return nil, err
	}
	if len(keyCSbuf) != 33 {
		return nil, taber.ErrInvalidIDLength
	}
	ik := IdentityKeys{Public: keyCSbuf[:len(keyCSbuf)-1]}
	cs := keyCSbuf[len(keyCSbuf)-1:]
	// TODO: Is constant time important here at all?
	// cs2 is guaranteed length 1 here or err will be a BadProgrammingError.
	cs2, err := ik.checksum()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(cs, cs2) {
		if err != nil {
			return nil, err
		}
		return nil, taber.ErrInvalidIDChecksum
	}
	return &ik, nil
}
