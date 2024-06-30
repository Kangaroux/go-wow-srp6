package srp

import (
	"encoding/csv"
	"encoding/hex"
	"os"
)

// mustLoadTestData reads a CSV containing test inputs and returns a 2D array of the rows and columns.
// Panics if an error occurs.
func mustLoadTestData(path string) [][]string {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		panic(err)
	}

	return rows
}

// mustDecodeHex returns a byte array parsed from the given hex string. Panics if an error occurs.
func mustDecodeHex(s string) []byte {
	val, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return val
}
