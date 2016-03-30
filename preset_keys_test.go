package minilock

var (
	testKey1ID         = "2Ddpk7j3cnyHRUNbukQTEagXFBHSGZV4suemTjEKyZs6BF"
	testKey2ID         = "bgJMMiCJiJL1jq48rkWc8cUfkuQWjRYKR44sHgK2kiUj1"
	testKey1, testKey2 *IdentityKeys
)

// Because of the work involved creating keys, they shouldn't be made within
// test cases as they wildly skew the time required.
func init() {
	testKey1, _ = IdentityFromEmailAndPassphrase("cathalgarvey@some.where", "this is a password that totally works for minilock purposes")
	testKey2, _ = IdentityFromEmailAndPassphrase("joeblocks@else.where", "whatever I write won't be good enough for the NSA")
}
