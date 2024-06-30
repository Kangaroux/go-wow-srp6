package srp

import (
	"crypto/sha1"
	"strings"
)

// ClientChallengeProof returns a proof that the client should send after receiving the auth challenge.
// The server should compare this with the proof received by the client and verify they match.
// If they match, the client has proven they know the session key.
func ClientChallengeProof(
	username string,
	salt,
	clientPublicKey,
	serverPublicKey,
	sessionKey []byte,
) []byte {
	hUsername := sha1.Sum([]byte(strings.ToUpper(username)))
	h := sha1.New()
	h.Write(xorHash)
	h.Write(hUsername[:])
	h.Write(salt)
	h.Write(clientPublicKey)
	h.Write(serverPublicKey)
	h.Write(sessionKey)
	return h.Sum(nil)
}

// ServerChallengeProof returns a proof that the server should send after validating the client proof.
// The server proof is not used when the client is reconnecting.
func ServerChallengeProof(clientPublicKey, clientProof, sessionKey []byte) []byte {
	h := sha1.New()
	h.Write(clientPublicKey)
	h.Write(clientProof)
	h.Write(sessionKey)
	return h.Sum(nil)
}

// ReconnectProof returns a proof that the client should send when attempting to reconnect.
// Like ClientChallengeProof, the server should compare this with the proof received by the client.
func ReconnectProof(username string, clientData, serverData, sessionKey []byte) []byte {
	h := sha1.New()
	h.Write([]byte(strings.ToUpper(username)))
	h.Write(clientData)
	h.Write(serverData)
	h.Write(sessionKey)
	return h.Sum(nil)
}

// WorldProof returns a proof that the client should send once they have finished authenticating
// and want to connect to the world/realm server.
func WorldProof(username string, clientSeed, serverSeed, sessionKey []byte) []byte {
	h := sha1.New()
	h.Write([]byte(strings.ToUpper(username)))
	h.Write([]byte{0, 0, 0, 0})
	h.Write(clientSeed)
	h.Write(serverSeed)
	h.Write(sessionKey)
	return h.Sum(nil)
}
