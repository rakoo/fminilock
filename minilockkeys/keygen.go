package minilockkeys

import (
  "github.com/cathalgarvey/go-minilock/minilockutils"
  "bytes"
  "crypto/rand"
  "golang.org/x/crypto/scrypt"
  "golang.org/x/crypto/nacl/box"
  "github.com/dchest/blake2s"
  "github.com/cathalgarvey/base58"
)

// NaCl box keys are used for miniLock after being derived from a passphrase
// using blake2s and scrypt. Ephemeral keys can also be generated directly from
// CSPRNG output.
// Keypairs are represented as IDs by appending a blake2s checksum byte and
// b58 encoding.
// The keypair used by miniLock is generated as-needed from a passphrase and
// salt (email) every time it is needed. So, there is no serialise/deserialise
// method for Private key material, as it should never be stored outside of RAM
// and because people who really want a serialisation of a valuable private key
// can always just store their passphrase in plain text and use that!
type NaClKeypair struct{
  // TODO: Refactor so key material is accessed through methods that can throw
  // early errors on invalid or missing key material.

  // May be empty for pubkey-only keypairs.
  Private []byte
  // Should always be full.
  Public []byte
}

func (self *NaClKeypair) hasPart(part []byte) bool {
  if part != nil && len(part) == 32 {
    return true
  } else {
    return false
  }
}

func (self *NaClKeypair) HasPublic() bool {
  return self.hasPart(self.Public)
}

func (self *NaClKeypair) HasPrivate() bool {
  return self.hasPart(self.Private)
}

func (self *NaClKeypair) PrivateArray() *[32]byte {
  arr := new([32]byte)
  copy(arr[:], self.Private)
  return arr
}

func (self *NaClKeypair) PublicArray() *[32]byte {
  arr := new([32]byte)
  copy(arr[:], self.Public)
  return arr
}

func (self *NaClKeypair) PublicOnly() *NaClKeypair {
  PK := new(NaClKeypair)
  PK.Public = make([]byte, len(self.Public))
  copy(PK.Public, self.Public)
  return PK
}

func Ephemeral() (*NaClKeypair, error) {
  rand_bytes := make([]byte, 32)
  read, err := rand.Read(rand_bytes)
  if err != nil {
    return nil, err
  }
  if read != 32 {
    return nil, minilockutils.SecInconsistencyError("In generating ephemeral key, asked for 32 bytes of rand.Reader but got some other number!")
  }
  rand_reader := bytes.NewReader(rand_bytes)
  public, private, err := box.GenerateKey(rand_reader)
  if err != nil {
    return nil, err
  }
  // Always be explicit about public/private material in case struct is
  // rearranged (/accidentally) later on
  return &NaClKeypair{Private: private[:], Public: public[:]}, nil
}

func FromEmailAndPassphrase(email, passphrase string) (*NaClKeypair, error) {
    pp_blake := blake2s.Sum256([]byte(passphrase))
    pp_scrypt, err := scrypt.Key(pp_blake[:], []byte(email), 131072, 8, 1, 32)
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
    return &NaClKeypair{Private: private[:], Public: public[:]}, nil
}

func FromID(id string) (*NaClKeypair, error) {
    key_cs_buf, err := base58.StdEncoding.Decode([]byte(id))
    if err != nil {
      return nil, err
    }
    if len(key_cs_buf) != 33 {
      return nil, minilockutils.KeyVerificationError("Provided public ID was not expected length (33 bytes when decoded): "+id)
    }
    kp := NaClKeypair{Public: key_cs_buf[:len(key_cs_buf)-1]}
    cs := key_cs_buf[len(key_cs_buf)-1:]
    // TODO: Is constant time important here at all?
    // cs_2 is guaranteed length 1 here or err will be a BadProgrammingError.
    cs_2, err := kp.checksum()
    if err != nil {
      return nil, err
    }
    if cs[0] != cs_2[0] {
      if err != nil {
        return nil, err
      } else {
        return nil, minilockutils.KeyVerificationError("Key checksum verification failed for ID: "+id)
      }
    }
    return &kp, nil
}

// Generate 1-byte checksum using blake2s.
func (self *NaClKeypair) checksum() ([]byte, error) {
  blakeHasher, err := blake2s.New(&blake2s.Config{Size: 1})
  if err != nil {
    return nil, err
  }
  _, err = blakeHasher.Write(self.Public)
  // TODO: Assert written is the correct size!
  // TODO: Assert blakeHasher.Size() == 1
  if err != nil {
    return nil, err
  }
  checksum := blakeHasher.Sum(nil)
  // TODO: Assert checksum is length 1!
  if len(checksum) != 1 {
    return nil, minilockutils.BadProgrammingError("Checksum generated was not length 1: "+string(base58.StdEncoding.Encode(checksum)))
  }
  return checksum, nil
}

// Generate base58-encoded pubkey+checksum.
func (self *NaClKeypair) EncodeID() (string, error) {
  plen := len(self.Public)
  idbuf := make([]byte, plen, plen + 1)
  copy(idbuf, self.Public)
  cs, err := self.checksum()
  if err != nil {
    return "", err
  }
  idbuf = append(idbuf, cs[0])
  id := base58.StdEncoding.Encode(idbuf)
  return string(id), nil
}
