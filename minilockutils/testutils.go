package minilockutils

// Used to verify that byte slices are the same. Does not check
// *addresses* of slices, merely that the contents are the same values.
func CmpSlices(a, b []byte) bool {
  if len(a) != len(b) {
    return false
  }
  for i, c := range a {
    if b[i] != c {
      return false
    }
  }
  return true
}
