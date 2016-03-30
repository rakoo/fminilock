package minilock

import (
	"bytes"
	"testing"
)

// Go-Bindata likes to know where to base paths when loading
// unit tests?
var rootDir = "."

func Test_ParseMinilockFile(t *testing.T) {
	testcase, err := Asset("binary_samples/mye.go.minilock")
	if err != nil {
		t.Fatal("Couldn't load test binary asset.")
	}
	expectedPlaintext, err := Asset("binary_samples/mye.go")
	if err != nil {
		t.Fatal("Couldn't load test binary asset.")
	}
	header, ciphertext, err := ParseFileContents(testcase)
	if err != nil {
		t.Fatal("Failed to parse testcase.")
	}

	recipient, _ := GenerateKey("cathalgarvey@some.where", "this is a password that totally works for minilock purposes")
	senderIdentityID, senderID, replyToID, filename, contents, err := header.DecryptContents(ciphertext, recipient)
	if err != nil {
		t.Fatal("Failed to decrypt with recipient: " + err.Error())
	}
	if senderIdentityID != testKey1ID {
		t.Error("SenderIdentityID was expected to be '", testKey1ID, "' but was: ", senderIdentityID)
	}
	if replyToID != "8nqVZubQa5abyNV1RhkW9Un8BcpFNqXGZaKQCe5obdFb6" {
		t.Error("ReplyToID was expected to be '8nqVZubQa5abyNV1RhkW9Un8BcpFNqXGZaKQCe5obdFb6' but was: ", replyToID)
	}
	if senderID != "Arv5UQQatYC7TvPVNWA6JLduApVMWoYV4f9DS2q5dRbt4" {
		t.Error("SenderID was expected to be 'Arv5UQQatYC7TvPVNWA6JLduApVMWoYV4f9DS2q5dRbt4' but was: " + senderID)
	}
	if filename != "mye.go" {
		t.Error("Filename returned should have been 'mye.go', was: " + filename)
	}
	if !bytes.Equal(contents, expectedPlaintext) {
		t.Error("Plaintext did not match expected plaintext.")
	}
	senderIdentityID2, senderID2, replyToID2, filename2, contents2, err := DecryptFileContents(testcase, recipient)
	if err != nil {
		t.Fatal("Failed to decrypt on second try with recipient: " + err.Error())
	}
	if senderIdentityID != senderIdentityID2 {
		t.Error("Inconsistency between senderIdentityID returned by DecryptFileContents and manual parsing/header decryption")
	}
	if replyToID != replyToID2 {
		t.Error("Inconsistency between replyToID returned by DecryptFileContents and manual parsing/header decryption")
	}
	if senderID != senderID2 {
		t.Error("Inconsistency between senderID returned by DecryptFileContents and manual parsing/header decryption.")
	}
	if filename != filename2 {
		t.Error("Inconsistency between filename returned by DecryptFileContents and manual parsing/header decryption.")
	}
	if !bytes.Equal(contents2, expectedPlaintext) {
		t.Error("Plaintext did not match expected plaintext.")
	}
}
