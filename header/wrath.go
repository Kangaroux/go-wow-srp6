package header

import (
	"crypto"
	"crypto/hmac"
	"crypto/rc4"
	"errors"
	"sync"
)

var (
	wrathDecryptKey = []byte{
		0xC2, 0xB3, 0x72, 0x3C, 0xC6, 0xAE, 0xD9, 0xB5,
		0x34, 0x3C, 0x53, 0xEE, 0x2F, 0x43, 0x67, 0xCE,
	}
	wrathEncryptKey = []byte{
		0xCC, 0x98, 0xAE, 0x04, 0xE8, 0x97, 0xEA, 0xCA,
		0x12, 0xDD, 0xC0, 0x93, 0x42, 0x91, 0x53, 0x57,
	}

	ErrCryptoNotInitialized = errors.New("header crypto has not been initialized")
)

// WrathCrypto is used for encrypting/decrypting world packet headers in WoTLK.
// Once the client has authenticated, all incoming/outgoing headers must be encrypted.
type WrathCrypto struct {
	decryptCipher *rc4.Cipher
	encryptCipher *rc4.Cipher
	sessionKey    []byte

	decryptMutex sync.Mutex
	encryptMutex sync.Mutex
}

// NewWrathCrypto returns a new WrathCrypto that uses sessionKey. Before the returned
// crypto object can be used, [Init] should be called to initialize the ciphers.
func NewWrathCrypto(sessionKey []byte) *WrathCrypto {
	return &WrathCrypto{sessionKey: sessionKey}
}

// Init initializes the ciphers with the standard encrypt/decrypt keys.
func (h *WrathCrypto) Init() error {
	return h.InitKeys(wrathDecryptKey, wrathEncryptKey)
}

// InitKeys initializes the ciphers. [Init] should be used instead, unless for some reason
// different keys are needed.
func (h *WrathCrypto) InitKeys(decryptKey, encryptKey []byte) error {
	decryptCipher, err := rc4.NewCipher(h.generateKey(decryptKey))
	if err != nil {
		return err
	}

	encryptCipher, err := rc4.NewCipher(h.generateKey(encryptKey))
	if err != nil {
		return err
	}

	h.decryptCipher = decryptCipher
	drop1024(h.decryptCipher)

	h.encryptCipher = encryptCipher
	drop1024(h.encryptCipher)

	return nil
}

// Decrypt decrypts a client header in-place. If the decrypt cipher is not initialized, Decrypt returns
// ErrCryptoNotInitialized. Decrypt is safe to use concurrently.
func (h *WrathCrypto) Decrypt(data []byte) error {
	if h.decryptCipher == nil {
		return ErrCryptoNotInitialized
	}

	h.decryptMutex.Lock()
	h.decryptCipher.XORKeyStream(data, data)
	h.decryptMutex.Unlock()

	return nil
}

// Encrypt encrypts a server header in-place. If the encrypt cipher is not initialized, Encrypt returns
// ErrCryptoNotInitialized. Encrypt is safe to use concurrently.
func (h *WrathCrypto) Encrypt(data []byte) error {
	if h.encryptCipher == nil {
		return ErrCryptoNotInitialized
	}

	h.encryptMutex.Lock()
	h.encryptCipher.XORKeyStream(data, data)
	h.encryptMutex.Unlock()

	return nil
}

// generateKey returns a cipher key based on key.
func (h *WrathCrypto) generateKey(key []byte) []byte {
	hash := hmac.New(crypto.SHA1.New, key)
	hash.Write(h.sessionKey)
	return hash.Sum(nil)
}

// drop1024 discards the first 1024 bytes of the keystream. This is a protection against a
// keystream attack. The client and server ciphers must stay in sync, since the client drops
// 1024, so does the server.
func drop1024(cipher *rc4.Cipher) {
	var drop1024 [1024]byte
	cipher.XORKeyStream(drop1024[:], drop1024[:])
}
