package srp

import (
	"math/big"

	"github.com/kangaroux/go-wow-srp6/internal"
)

// bytesToInt returns a little endian big integer from a big endian byte array.
func bytesToInt(data []byte) *big.Int {
	return big.NewInt(0).SetBytes(internal.Reverse(data))
}

// intToBytes returns a big endian byte array from a little endian big integer.
func intToBytes(padding int, bi *big.Int) []byte {
	return internal.Reverse(internal.Pad(padding, bi.Bytes()))
}
