package minilock

import (
	"github.com/cathalgarvey/go-minilock/minilockkeys"
)

var (
	testKey1ID         = "2453m8h7r3stzV8NeG4WzrFhsXTTsXTodQA2S6R9J2dfuh"
	testKey2ID         = "xjjCm44Nuj4DyTBuzguJ1d7K6EdP2TWRYzsqiiAbfcGTr"
	testKey1, testKey2 *minilockkeys.NaClKeypair
)

// Because of the work involved creating keys, they shouldn't be made within
// test cases as they wildly skew the time required.
func init() {
	testKey1, _ = minilockkeys.FromEmailAndPassphrase("cathalgarvey@some.where", "this is a password that totally works for minilock purposes")
	testKey2, _ = minilockkeys.FromEmailAndPassphrase("joeblocks@else.where", "whatever I write won't be good enough for the NSA")
}
