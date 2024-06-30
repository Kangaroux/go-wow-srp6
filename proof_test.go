package srp

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientProof(t *testing.T) {
	rows := mustLoadTestData("testdata/calculate_client_proof.csv")

	t.Run("generated test data", func(t *testing.T) {
		for _, row := range rows {
			username := row[0]
			salt := mustDecodeHex(row[1])
			clientPublic := mustDecodeHex(row[2])
			serverPublic := mustDecodeHex(row[3])
			sessionKey := mustDecodeHex(row[4])
			expected := mustDecodeHex(row[5])

			assert.Equal(t, expected, ClientChallengeProof(username, salt, clientPublic, serverPublic, sessionKey))
		}
	})

	t.Run("username is case insensitive", func(t *testing.T) {
		row := rows[0]
		username := row[0]
		salt := mustDecodeHex(row[1])
		clientPublic := mustDecodeHex(row[2])
		serverPublic := mustDecodeHex(row[3])
		sessionKey := mustDecodeHex(row[4])

		first := ClientChallengeProof(strings.ToLower(username), salt, clientPublic, serverPublic, sessionKey)
		second := ClientChallengeProof(strings.ToUpper(username), salt, clientPublic, serverPublic, sessionKey)

		assert.Equal(t, first, second)
	})
}

func TestServerProof(t *testing.T) {
	rows := mustLoadTestData("testdata/calculate_server_proof.csv")

	for _, row := range rows {
		clientPublic := mustDecodeHex(row[0])
		clientProof := mustDecodeHex(row[1])
		sessionKey := mustDecodeHex(row[2])
		expected := mustDecodeHex(row[3])

		assert.Equal(t, expected, ServerChallengeProof(clientPublic, clientProof, sessionKey))
	}
}

func TestReconnectProof(t *testing.T) {
	rows := mustLoadTestData("testdata/calculate_reconnect_proof.csv")

	t.Run("generated test data", func(t *testing.T) {
		for _, row := range rows {
			username := row[0]
			clientData := mustDecodeHex(row[1])
			serverData := mustDecodeHex(row[2])
			sessionKey := mustDecodeHex(row[3])
			expected := mustDecodeHex(row[4])

			assert.Equal(t, expected, ReconnectProof(username, clientData, serverData, sessionKey))
		}
	})

	t.Run("username is case insensitive", func(t *testing.T) {
		row := rows[0]
		username := row[0]
		clientData := mustDecodeHex(row[1])
		serverData := mustDecodeHex(row[2])
		sessionKey := mustDecodeHex(row[3])

		first := ReconnectProof(strings.ToLower(username), clientData, serverData, sessionKey)
		second := ReconnectProof(strings.ToUpper(username), clientData, serverData, sessionKey)

		assert.Equal(t, first, second)
	})
}

func TestCalculateWorldProof(t *testing.T) {
	t.Skip("FIXME")

	expected := mustDecodeHex("6095EB678CD195253F66F32BADA785CA6D9376B2")
	username := "TNDQWSHEBWHPABV2"
	clientSeed := make([]byte, 4)
	serverSeed := make([]byte, 4)
	binary.BigEndian.PutUint32(clientSeed, 1454143186)
	binary.BigEndian.PutUint32(serverSeed, 309086257)
	sessionKey := mustDecodeHex("914D6219A99109D6BD946F6E6AF12BB611C59A22531C6F1A3F3CF58624D528DC163BE43813112C3D")

	assert.Equal(t, expected, WorldProof(username, clientSeed, serverSeed, sessionKey))
}
