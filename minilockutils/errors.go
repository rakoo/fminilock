package minilockutils

type BadArgumentError string
func (self BadArgumentError) Error() string {
  return string(self)
}

// Returned when programmer error shit happens like wrong-length checksums.
type BadProgrammingError string
func (self BadProgrammingError) Error() string {
  return string(self)
}

// Raised for stuff like "I asked for 32 random bytes and didn't get 32 bytes
// but rand.Read didn't return an error" (hint: this is exactly what it is
// returned for at time of writing..)
type SecInconsistencyError string
func (self SecInconsistencyError) Error() string {
  return string(self)
}

type KeyVerificationError string
func (self KeyVerificationError) Error() string {
  return string(self)
}

// Raised on failure to decrypt things.
type DecryptionError string
func (self DecryptionError) Error() string {
  return string(self)
}

// Signature / Authentication failure.
type AuthenticationError string
func (self AuthenticationError) Error() string {
  return string(self)
}

// Malicious or Erroneous Encoding: False length prefixes, etcetera.
type BadEncodingError string
func (self BadEncodingError) Error() string {
  return string(self)
}
