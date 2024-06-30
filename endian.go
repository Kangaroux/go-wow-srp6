package srp

import (
	"math/big"
)

// BytesToInt returns a little endian big integer from a big endian byte array.
func BytesToInt(data []byte) *big.Int {
	return big.NewInt(0).SetBytes(Reverse(data))
}

// IntToBytes returns a big endian byte array from a little endian big integer.
func IntToBytes(padding int, bi *big.Int) []byte {
	return Reverse(Pad(padding, bi.Bytes()))
}

// Pad adds zero-bytes as padding to a byte array if the array is smaller than the given length.
// If the array doesn't need padding, the original array is returned, otherwise a copy with padding
// included is returned.
func Pad(length int, data []byte) []byte {
	dataLen := len(data)
	if dataLen >= length {
		return data
	}
	ret := make([]byte, length)
	copy(ret[length-dataLen:], data)
	return ret
}

// Reverse returns a copy of the given byte array in reverse order.
func Reverse(data []byte) []byte {
	n := len(data)
	newData := make([]byte, n)
	for i := 0; i < n; i++ {
		newData[i] = data[n-i-1]
	}
	return newData
}
