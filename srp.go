// Package srp implements the SRP6 variant used in World of Warcraft.
//
// See the README for more info: https://github.com/kangaroux/go-wow-srp6
package srp

import (
	"crypto/sha1"
	"math/big"
	"strings"
)

// PasswordVerifier returns a 32 byte array containing the verifier. The verifier is a shared secret.
// The server should store it and ensure it is never made public.
func PasswordVerifier(username, password string, salt []byte) []byte {
	x := bytesToInt(calculateX(username, password, salt))
	return intToBytes(VerifierSize, big.NewInt(0).Exp(g, x, n))
}

// ServerPublicKey returns a 32 byte public key. The private key should be a 32 byte array
// cryptographically secure random data ([crypto/rand]). The server should send the public key
// to the client in plaintext.
func ServerPublicKey(verifier, serverPrivateKey []byte) []byte {
	publicKey := big.NewInt(0).Exp(g, bytesToInt(serverPrivateKey), n)
	kv := big.NewInt(0).Mul(k, bytesToInt(verifier))
	return intToBytes(KeySize, publicKey.Add(publicKey, kv).Mod(publicKey, n))
}

// SessionKey returns a 40 byte key that will be used for header encryption/decryption.
// The session key should never be made public.
func SessionKey(clientPublicKey, serverPublicKey, serverPrivateKey, verifier []byte) []byte {
	u := calculateU(clientPublicKey, serverPublicKey)
	S := calculateServerSKey(clientPublicKey, verifier, u, serverPrivateKey)
	return calculateInterleave(S)
}

// calculateServerSKey returns an intermediate 32 byte key used to generate the session key.
func calculateServerSKey(clientPublicKey, verifier, u, serverPrivateKey []byte) []byte {
	S := big.NewInt(0).Exp(bytesToInt(verifier), bytesToInt(u), n)
	S.Mul(S, bytesToInt(clientPublicKey))
	S.Exp(S, bytesToInt(serverPrivateKey), n)
	return intToBytes(KeySize, S)
}

// calculateInterleave returns a 40 byte array containing an interleaved S-key.
func calculateInterleave(S []byte) []byte {
	// If the leading byte is zero, remove the leading TWO bytes
	for len(S) > 0 && S[0] == 0 {
		S = S[2:]
	}

	lenS := len(S)
	even, odd := make([]byte, lenS/2), make([]byte, lenS/2)

	// Split the even/odd bytes into separate arrays
	for i := 0; i < lenS/2; i++ {
		even[i] = S[i*2]
		odd[i] = S[i*2+1]
	}

	hEven := sha1.Sum(even)
	hOdd := sha1.Sum(odd)
	interleaved := make([]byte, 40)

	// Interleave the even bytes and odd bytes together, alternating each byte
	for i := 0; i < 20; i++ {
		interleaved[i*2] = hEven[i]
		interleaved[i*2+1] = hOdd[i]
	}

	return interleaved
}

// calculateX returns an intermediate value used for generating the password verifier.
func calculateX(username, password string, salt []byte) []byte {
	h := sha1.New()
	inner := sha1.Sum([]byte(strings.ToUpper(username) + ":" + strings.ToUpper(password)))
	h.Write(salt)
	h.Write(inner[:])
	return h.Sum(nil)
}

// calculateU returns an intermediate value used for generating the session key.
func calculateU(clientPublicKey, serverPublicKey []byte) []byte {
	h := sha1.New()
	h.Write(clientPublicKey)
	h.Write(serverPublicKey)
	return h.Sum(nil)
}
