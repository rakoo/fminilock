package minilockbox

import (
  "fmt"
  "bytes"
  "testing"
  "encoding/base64"
)

func Test_NonceGen(t *testing.T) {
  base_nonce := []byte("0123456789012345")
  first_6_nonces := make([][]byte, 0, 6)
  n1, _ := base64.StdEncoding.DecodeString("MDEyMzQ1Njc4OTAxMjM0NQAAAAAAAAAA")
  first_6_nonces = append(first_6_nonces, n1)
  n2, _ := base64.StdEncoding.DecodeString("MDEyMzQ1Njc4OTAxMjM0NQEAAAAAAAAA")
  first_6_nonces = append(first_6_nonces, n2)
  n3, _ := base64.StdEncoding.DecodeString("MDEyMzQ1Njc4OTAxMjM0NQIAAAAAAAAA")
  first_6_nonces = append(first_6_nonces, n3)
  n4, _ := base64.StdEncoding.DecodeString("MDEyMzQ1Njc4OTAxMjM0NQMAAAAAAAAA")
  first_6_nonces = append(first_6_nonces, n4)
  n5, _ := base64.StdEncoding.DecodeString("MDEyMzQ1Njc4OTAxMjM0NQQAAAAAAAAA")
  first_6_nonces = append(first_6_nonces, n5)
  n6, _ := base64.StdEncoding.DecodeString("MDEyMzQ1Njc4OTAxMjM0NQUAAAAAAAAA")
  first_6_nonces = append(first_6_nonces, n6)
  for i, nonce := range first_6_nonces {
    n, err := makeChunkNonce(base_nonce, i, false)
    if err != nil {
      t.Error(err.Error())
    }
    if !bytes.Equal(n, nonce) {
      t.Error("Nonces don't match:\n\tExpected: ", nonce, "\n\tCreated: ", n)
    }
  }
  ch_12_last, _ := base64.StdEncoding.DecodeString("MDEyMzQ1Njc4OTAxMjM0NQsAAAAAAACA")
  last_nonce, err := makeChunkNonce(base_nonce, 11, true)
  if err != nil {
    t.Error(err.Error())
  }
  if !bytes.Equal(last_nonce, ch_12_last) {
    t.Error("Nonces don't match:\n\tExpected: ", ch_12_last, "\n\tCreated: ", last_nonce)
  }
}

func Test_BlockRoundTrip(t *testing.T) {
  plaintext := []byte("This is a file and the contents aren't very long, but it'll suffice for testing one-block encryption.")
  key := []byte("12345678901234567890123456789012")  // 32 bytes
  base_nonce := []byte("1234567890123456")
  ciphertext, err := encryptChunk(key, base_nonce, plaintext, 1, false)
  if err != nil {
    t.Error(err.Error())
  }
  decrypted, err := decryptBlock(key, base_nonce, ciphertext)
  if err != nil {
    t.Error(err.Error())
  }
  if !bytes.Equal(decrypted, plaintext) {
    t.Error("Decrypted block did not equal original plaintext:",
      "\nOriginal:\t", plaintext,
      "\nDecryptd:\t", decrypted)
  }
  fmt.Println("Now testing Ciphertext walking.")
  blocks, err := walkCiphertext(ciphertext.Block)
  if err != nil {
    t.Error(err.Error())
  }
  if len(blocks) == 0 {
    t.Fatal("Unable to parse any blocks from ciphertext..")
  }
  if !bytes.Equal(ciphertext.Block, blocks[0].Block) {
    t.Error("Decrypted block did not equal original plaintext:",
      "\nBlock :\t", ciphertext.Block,
      "\nWalked:\t", blocks[0].Block)
  }
}

func Test_OneBlockEncrypt(t *testing.T) {
  plaintext := []byte("This is a file and the contents aren't very long, but it'll suffice for testing one-block encryption.")
  plaintextfn := "This is a filename.txt"
  key := []byte("12345678901234567890123456789012")  // 32 bytes
  basenonce := []byte("1234567890123456")
  expected, err := base64.StdEncoding.DecodeString("AAEAAPdoXdukrJcgTxCpDnZDNdPO74bS/SFfQ5B1Sh44jD7799Hl8qK2UoqUGBdgI1qGuQMKS5JeAczkQPtIRD+bIDflLZOfrhSC1JlkAQv0AuGEpMnGvUVUobWyat6DlutN9EAoqasW5NOgT8Bv1lLWjohs3WOhTv+ZtIu7UpWdeiDV/T/jV5Tl8yAUq5PN00oBnKHttG5akrDsMmwyN14drnZAxblHz5Qq9my9p22D6GY/W7QfBaXiBGXdPQR/vtQuTyMWahPP4PKLLv/FDAiJWJajla6neEkZtpYPTSL0kyzGpHbF009r5siUzTLHuLlmI5bLDIb1OO6rWihygHWHp1z0qXVYgfW5dZFMACk0+w2UZQAAAIvQDRpt3Nr+R/wbSS4giTLIdh8TIowyCUj493Tew5/iOyfi+xdG7vfdFg9qnHbL2kwONFBJbEdbYOgWvErM3cah2jH6+vmXbPCGF7E33m59UlIcYBgPHuH+5Uaoo/1ebK3uytKBCSr214wsUN22gRi0flSGWQ==")
  if err != nil {
    t.Error(err.Error())
  }
  if testing.Verbose() {
    fmt.Println("Creating demo ciphertext.")
  }
  ciphertext, err := Encrypt(plaintextfn, key, basenonce, plaintext)
  if err != nil {
    t.Error(err.Error())
  }
  if testing.Verbose() {
    fmt.Println("Finished, comparing to known example.")
  }
  if len(ciphertext) != len(expected) {
    t.Error("Length of expected vs. ciphertext differed: ", len(expected), "vs", len(ciphertext))
  }
  if !bytes.Equal(ciphertext, expected) {
    t.Error("Ciphertext did not match expected result: \nCT:\t", ciphertext, "\nExp:\t", expected)
  }
  // Now also test decryption.
}

func Test_ManyBlockEncrypt(t *testing.T) {
  if testing.Verbose() {
    fmt.Println("Preparing a longer plaintext for encryption..")
  }
  plaintext := make([]byte, 167 + chunk_size * 10)
  for _, ch := range chunkify(plaintext, 100) {
    copy(ch, []byte(" this is a longer message consisting of 100 characters, repeated ad nauseum to create a test case.. "))
  }
  if len(plaintext) != (167 + (chunk_size * 10)) {
    t.Error("Failed to create test case of expected length.")
  }
  plaintextfn := "This is another filename.txt"
  key := []byte("01234567890123456789012345678901")  // 32 bytes
  basenonce := []byte("0123456789012345")
  // Sample encrypted testcase included in 'testcase_test.go' as var b64_long_testcase (string)
  expected, err := base64.StdEncoding.DecodeString(b64_long_testcase)
  if err != nil {
    t.Error(err.Error())
  }
  if testing.Verbose() {
    fmt.Println("Creating demo ciphertext.")
  }
  ciphertext, err := Encrypt(plaintextfn, key, basenonce, plaintext)
  if err != nil {
    t.Error(err.Error())
  }
  if testing.Verbose() {
    fmt.Println("Finished, comparing to known example.")
  }
  if len(ciphertext) != len(expected) {
    t.Error("Length of expected vs. ciphertext differed: ", len(expected), "vs", len(ciphertext))
  }
  ch_size := 500
  ct_chunks := chunkify(ciphertext, ch_size)
  ex_chunks := chunkify(expected, ch_size)
  for i := 0; i < len(ct_chunks); i++ {
    if !bytes.Equal(ct_chunks[i], ex_chunks[i]) {
      t.Fatal("Comparison of ciphertext:expected chunks failed at chunk #", i,
          ":\nExpected:\t",ex_chunks[i],
           "\nCiphertx:\t",ct_chunks[i])
    }
  }
  // Now also test decryption.
  filename, decrypted, err := Decrypt(key, basenonce, ciphertext)
  if err != nil {
    t.Fatal(err.Error())
  }
  if filename != plaintextfn {
    t.Error("Filename parsed from ciphertext didn't match input: ", filename, "Should have been:", plaintextfn)
  }
  pt_chunks := chunkify(plaintext, ch_size)
  pt2_chunks := chunkify(decrypted, ch_size)
  for i := 0; i < len(pt_chunks); i++ {
    if !bytes.Equal(pt_chunks[i], pt2_chunks[i]) {
      t.Fatal("Comparison of plaintext:decrypted chunks failed at chunk #", i,
          ":\nExpected:\t",pt_chunks[i],
           "\nDecryptd:\t",pt2_chunks[i])
    }
  }
}
