package internal

// Pad returns a copy of data appended with zeroed bytes. Padding is added until len(data) == length.
// Initially, if len(data) >= length, no padding is added and the original data is returned.
func Pad(length int, data []byte) []byte {
	dataLen := len(data)
	if dataLen >= length {
		return data
	}
	ret := make([]byte, length)
	copy(ret[length-dataLen:], data)
	return ret
}

// Reverse returns a copy of data in Reverse order.
func Reverse(data []byte) []byte {
	n := len(data)
	newData := make([]byte, n)
	for i := 0; i < n; i++ {
		newData[i] = data[n-i-1]
	}
	return newData
}
