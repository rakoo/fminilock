package minilockkeys

import (
  "testing"
  "encoding/base64"
  "github.com/cathalgarvey/base58"
  "github.com/cathalgarvey/go-minilock/minilockutils"
)

func Test_base58(t *testing.T) {
  vector, err := base64.StdEncoding.DecodeString("ZmCKWdGYhJ8pQr9JrKZXolLa16Z8yVOUfSl5ixxv")
  if err != nil {
    t.Fatal(err.Error())
  }
  test_b58, err := base58.StdEncoding.Decode([]byte("MWnnj3uJUTcSGJgBii46bpBnYhPQXeek7CZp1U6MU"))
  if err != nil {
    t.Fatal(err.Error())
  }
  if !minilockutils.CmpSlices(vector, test_b58) {
    t.Error("Base58 decoding failed:\n Vector: ", vector, "\n Decd'd: ", test_b58)
  }
  vector2, err := base64.StdEncoding.DecodeString("r8+3mEzmBWqTAEu0hy7pTxiqUiDMV68Evr7vqENQ")
  if err != nil {
    t.Fatal(err.Error())
  }
  test2_b58, err := base58.StdEncoding.Decode([]byte("cEDXP7UVaR4e8xnYsiQhGtN6k1Fp2ePBoscdvLS6b"))
  if err != nil {
    t.Fatal(err.Error())
  }
  if !minilockutils.CmpSlices(vector2, test2_b58) {
    t.Error("Base58 decoding failed:\n Vector: ", vector2, "\n Decd'd: ", test2_b58)
  }
}

func Test_Keygen(t *testing.T) {
  test_id := "2453m8h7r3stzV8NeG4WzrFhsXTTsXTodQA2S6R9J2dfuh"
  test_private_key, err := base64.StdEncoding.DecodeString("R92JSkvKPQzkRbcxpqQ4wNjc3uepTUlScG9n5cyGl6s=")
  if err != nil {
    t.Fatal(err.Error())
  }
  test_public_key, err := base64.StdEncoding.DecodeString("zZRIJ9myJk2fncUGmb1wr9zHC94K5kzSAXSkrT7GEiI=")
  if err != nil {
    t.Fatal(err.Error())
  }
  gen_key, err := FromEmailAndPassphrase("cathalgarvey@some.where", "this is a password that totally works for minilock purposes")
  if err != nil {
    t.Fatal(err.Error())
  }
  if !minilockutils.CmpSlices(test_private_key, gen_key.Private) {
    t.Fatal("Generated private key does not match test key:\n ", test_private_key,"\n ", gen_key.Private)
  }
  if !minilockutils.CmpSlices(test_public_key, gen_key.Public) {
    t.Fatal("Generated public key does not match test key:\n ", test_public_key,"\n ", gen_key.Public)
  }
  gen_id, err := gen_key.EncodeID()
  if err != nil {
    t.Fatal(err.Error())
  }
  if gen_id != test_id {
    t.Fatal("IDs do not match:\n Test ID:", test_id, "\n Gener'd:", gen_id)
  }
  pub_from_id, err :=  FromID(test_id)
  if err != nil {
    t.Fatal(err.Error())
  }
  if !minilockutils.CmpSlices(pub_from_id.Public, gen_key.Public) {
    t.Fatal("ID-imported public key does not match test key:\n ", test_public_key,"\n ", gen_key.Public)
  }
}
