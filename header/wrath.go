package header

import (
	"crypto"
	"crypto/hmac"
	"crypto/rc4"
	"errors"
	"sync"
)

const (
	// 23 bits + 1 bit for LARGE_HEADER_FLAG
	sizeFieldMaxValue = 0x7FFFFF

	// 15 bits (16th bit is reserved for LARGE_HEADER_FLAG)
	largeHeaderThreshold = 0x7FFF

	// Set on MSB of size field (first header byte)
	largeHeaderFlag = 0x80
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

	ErrCryptoNotInitialized = errors.New("srp/header: header crypto has not been initialized")
	ErrHeaderSizeTooLarge   = errors.New("srp/header: header size is too large")
)

// WrathHeader is used for encrypting/decrypting world packet headers in WoTLK.
// Once the client has authenticated, all incoming/outgoing headers must be encrypted.
type WrathHeader struct {
	decryptCipher *rc4.Cipher
	encryptCipher *rc4.Cipher

	decryptMutex sync.Mutex
	encryptMutex sync.Mutex
}

// Encode returns a header with opcode and size. Encode expects size to not include the
// 2 bytes for the opcode, and will add +2 to size. In WoTLK, server headers can be either
// 4 or 5 bytes. Headers will automatically be encrypted if [Init] was called.
func (h *WrathHeader) Encode(opcode uint16, size uint32) ([]byte, error) {
	// Include the opcode in the size
	size += 2

	if size > sizeFieldMaxValue {
		return nil, ErrHeaderSizeTooLarge
	}

	var header []byte

	// The size field in the header can be 2 or 3 bytes. If the size field is 3 bytes, the MSB of the
	// size will be set.
	//
	// The header format is: <size><opcode>
	// <size> is 2-3 bytes big endian
	// <opcode> is 2 bytes little endian
	if size > largeHeaderThreshold {
		header = []byte{
			byte(size>>16) | largeHeaderFlag,
			byte(size >> 8),
			byte(size),
			byte(opcode),
			byte(opcode >> 8),
		}
	} else {
		header = []byte{
			byte(size >> 8),
			byte(size),
			byte(opcode),
			byte(opcode >> 8),
		}
	}

	if h.encryptCipher != nil {
		if err := h.Encrypt(header); err != nil {
			return nil, err
		}
	}

	return header, nil
}

// Init sets up the ciphers using sessionKey. Init must be called before trying to
// use [Encrypt] or [Decrypt].
func (h *WrathHeader) Init(sessionKey []byte) error {
	return h.InitKeys(sessionKey, wrathDecryptKey, wrathEncryptKey)
}

// InitKeys initializes the ciphers. [Init] should be used instead, unless for some reason
// different keys are needed.
func (h *WrathHeader) InitKeys(sessionKey, decryptKey, encryptKey []byte) error {
	decryptCipher, err := rc4.NewCipher(h.generateKey(sessionKey, decryptKey))
	if err != nil {
		return err
	}

	encryptCipher, err := rc4.NewCipher(h.generateKey(sessionKey, encryptKey))
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
func (h *WrathHeader) Decrypt(data []byte) error {
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
func (h *WrathHeader) Encrypt(data []byte) error {
	if h.encryptCipher == nil {
		return ErrCryptoNotInitialized
	}

	h.encryptMutex.Lock()
	h.encryptCipher.XORKeyStream(data, data)
	h.encryptMutex.Unlock()

	return nil
}

// generateKey returns a cipher key based on key.
func (h *WrathHeader) generateKey(sessionKey, key []byte) []byte {
	hash := hmac.New(crypto.SHA1.New, key)
	hash.Write(sessionKey)
	return hash.Sum(nil)
}

// drop1024 discards the first 1024 bytes of the keystream. This is a protection against a
// keystream attack. The client and server ciphers must stay in sync, since the client drops
// 1024, so does the server.
func drop1024(cipher *rc4.Cipher) {
	var drop1024 [1024]byte
	cipher.XORKeyStream(drop1024[:], drop1024[:])
}
