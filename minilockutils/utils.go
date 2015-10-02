package minilockutils

import (
  //"fmt"
  "bytes"
  "encoding/binary"
  "crypto/rand"
)


// Return a slice of slices representing <chunk_length> chunks of <data>,
// excepting the last chunk which may be truncated.
func Chunkify(data []byte, chunk_length int) [][]byte {
  dlen := len(data)
  num_chunks := NumChunks(dlen, chunk_length)
  output := make([][]byte, 0, num_chunks)
  // Populate chunk slices
  for cn := 0; cn < num_chunks; cn++ {
    chunk_begin := cn * chunk_length
    chunk_end := chunk_begin + chunk_length
    if chunk_end > dlen {
      chunk_end = dlen
    }
    this_chunk := data[chunk_begin:chunk_end]
    output = append(output, this_chunk)
  }
  return output
}

func NumChunks(data_length, chunk_length int) int {
  num_chunks := data_length / chunk_length
  if (data_length % chunk_length) > 0 {
    num_chunks = num_chunks + 1
  }
  return num_chunks
}


func RandBytes(i int) ([]byte, error) {
  rand_bytes := make([]byte, i)
  read, err := rand.Read(rand_bytes)
  if err != nil {
    return nil, err
  }
  if read != i {
    return nil, SecInconsistencyError("In rand_bytes, did not receive requested number of bytes.")
  }
  return rand_bytes, nil
}

func MakeBaseNonce() ([]byte, error) {
  return RandBytes(16)
}

func MakeFullNonce() ([]byte, error) {
  return RandBytes(24)
}

func MakeSymmetricKey() ([]byte, error) {
  return RandBytes(32)
}

func NonceToArray(n []byte) (*[24]byte) {
  na := new([24]byte)
  copy(na[:], n)
  return na
}

func KeyToArray(k []byte) (*[32]byte) {
  ka := new([32]byte)
  copy(ka[:], k)
  return ka
}



func ToLittleEndian(i int32) ([]byte, error) {
  buf := new(bytes.Buffer)
  err := binary.Write(buf, binary.LittleEndian, i)
  if err != nil {
    return nil, err
  }
  return buf.Bytes(), nil
}

func FromLittleEndian(buf []byte) (int32, error) {
    var output int32
    buf_reader := bytes.NewReader(buf)
    err := binary.Read(buf_reader, binary.LittleEndian, &output)
    if err != nil {
      return 0, err
    }
    return output, nil
}
