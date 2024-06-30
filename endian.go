package srp

import (
	"math/big"
)

// bytesToInt returns a little endian big integer from a big endian byte array.
func bytesToInt(data []byte) *big.Int {
	return big.NewInt(0).SetBytes(reverse(data))
}

// intToBytes returns a big endian byte array from a little endian big integer.
func intToBytes(padding int, bi *big.Int) []byte {
	return reverse(pad(padding, bi.Bytes()))
}

// pad returns a copy of data appended with zeroed bytes. Padding is added until len(data) == length.
// Initially, if len(data) >= length, no padding is added and the original data is returned.
func pad(length int, data []byte) []byte {
	dataLen := len(data)
	if dataLen >= length {
		return data
	}
	ret := make([]byte, length)
	copy(ret[length-dataLen:], data)
	return ret
}

// reverse returns a copy of data in reverse order.
func reverse(data []byte) []byte {
	n := len(data)
	newData := make([]byte, n)
	for i := 0; i < n; i++ {
		newData[i] = data[n-i-1]
	}
	return newData
}
