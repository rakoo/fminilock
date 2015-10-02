package minilockbox

import (
  "fmt"
  "testing"
)

func TestChunkify(t *testing.T) {
  input := []byte("123456789012345678901234567890112345678901234567890123456789012345678901")
  cs := chunkify(input, 31)
  if len(cs[0]) != 31 || len(cs[1]) != 31 || len(cs[2]) != 10 {
    fmt.Println("Expected lengths 31, 31, 10 for chunked slice, got: ", len(cs[0]), len(cs[1]), len(cs[2]))
    fmt.Println("Input: ", input)
    fmt.Println("cs: ", cs)
  }
}
