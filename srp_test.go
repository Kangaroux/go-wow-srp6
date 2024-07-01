package srp

import (
	"strings"
	"testing"

	"github.com/kangaroux/go-wow-srp6/internal"
	"github.com/stretchr/testify/assert"
)

func TestX(t *testing.T) {
	rows := internal.MustLoadTestData("testdata/srp/calculate_x.csv")

	t.Run("generated test data", func(t *testing.T) {
		for _, row := range rows {
			username := row[0]
			password := row[1]
			salt := internal.MustDecodeHex(row[2])
			expected := internal.MustDecodeHex(row[3])

			assert.Equal(t, expected, calculateX(username, password, salt))
		}
	})

	t.Run("username/pass are case insensitive", func(t *testing.T) {
		row := rows[0]
		username := row[0]
		password := row[1]
		salt := internal.MustDecodeHex(row[2])

		first := calculateX(strings.ToLower(username), strings.ToLower(password), salt)
		second := calculateX(strings.ToUpper(username), strings.ToUpper(password), salt)

		assert.Equal(t, first, second)
	})
}

func TestVerifier(t *testing.T) {
	rows := internal.MustLoadTestData("testdata/srp/calculate_verifier.csv")

	t.Run("generated test data", func(t *testing.T) {
		for _, row := range rows {
			username := row[0]
			password := row[1]
			salt := internal.MustDecodeHex(row[2])
			expected := internal.MustDecodeHex(row[3])

			assert.Equal(t, expected, PasswordVerifier(username, password, salt))
		}
	})

	t.Run("username/pass are case insensitive", func(t *testing.T) {
		row := rows[0]
		username := row[0]
		password := row[1]
		salt := internal.MustDecodeHex(row[2])

		first := PasswordVerifier(strings.ToLower(username), strings.ToLower(password), salt)
		second := PasswordVerifier(strings.ToUpper(username), strings.ToUpper(password), salt)

		assert.Equal(t, first, second)
	})
}

func TestServerPublicKey(t *testing.T) {
	rows := internal.MustLoadTestData("testdata/srp/calculate_server_public_key.csv")

	for _, row := range rows {
		verifier := internal.MustDecodeHex(row[0])
		privateKey := internal.MustDecodeHex(row[1])
		expected := internal.MustDecodeHex(row[2])

		assert.Equal(t, expected, ServerPublicKey(verifier, privateKey))
	}
}

func TestCalculateU(t *testing.T) {
	rows := internal.MustLoadTestData("testdata/srp/calculate_u.csv")

	for _, row := range rows {
		clientPublic := internal.MustDecodeHex(row[0])
		serverPublic := internal.MustDecodeHex(row[1])
		expected := internal.MustDecodeHex(row[2])

		assert.Equal(t, expected, calculateU(clientPublic, serverPublic))
	}
}

func TestServerSKey(t *testing.T) {
	rows := internal.MustLoadTestData("testdata/srp/calculate_server_s.csv")

	for _, row := range rows {
		clientPublic := internal.MustDecodeHex(row[0])
		verifier := internal.MustDecodeHex(row[1])
		u := internal.MustDecodeHex(row[2])
		serverPrivate := internal.MustDecodeHex(row[3])
		expected := internal.MustDecodeHex(row[4])

		assert.Equal(t, expected, calculateServerSKey(clientPublic, verifier, u, serverPrivate))
	}
}

func TestInterleave(t *testing.T) {
	rows := internal.MustLoadTestData("testdata/srp/calculate_interleaved.csv")

	for _, row := range rows {
		s := internal.MustDecodeHex(row[0])
		expected := internal.MustDecodeHex(row[1])

		assert.Equal(t, expected, calculateInterleave(s))
	}
}

func TestServerSessionKey(t *testing.T) {
	rows := internal.MustLoadTestData("testdata/srp/calculate_server_session_key.csv")

	for _, row := range rows {
		clientPublic := internal.MustDecodeHex(row[0])
		serverPrivate := internal.MustDecodeHex(row[1])
		verifier := internal.MustDecodeHex(row[2])
		expected := internal.MustDecodeHex(row[3])
		serverPublic := ServerPublicKey(verifier, serverPrivate)

		assert.Equal(t, expected, SessionKey(clientPublic, serverPublic, serverPrivate, verifier))
	}
}
