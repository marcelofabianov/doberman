package hasher

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
)

func TestArgo2Hasher(t *testing.T) {
	password := "my-secret-password-123"

	t.Run("Success: Hash and Compare with default config", func(t *testing.T) {
		hasher := NewArgo2Hasher(nil)
		hashedPassword, err := hasher.Hash(password)
		require.NoError(t, err)
		require.NotEmpty(t, hashedPassword)

		match, err := hasher.Compare(password, hashedPassword)
		assert.NoError(t, err)
		assert.True(t, match)

		match, err = hasher.Compare("wrong-password", hashedPassword)
		assert.ErrorIs(t, err, ErrMismatch)
		assert.False(t, match)
	})

	t.Run("Success: Hash and Compare with custom config", func(t *testing.T) {
		customConfig := &Config{
			time:        1,
			memory:      128 * 1024, // 128MB
			parallelism: 2,
			saltLength:  16,
			keyLength:   32,
		}
		hasher := NewArgo2Hasher(customConfig)
		hashedPassword, err := hasher.Hash(password)
		require.NoError(t, err)

		match, err := hasher.Compare(password, hashedPassword)
		assert.NoError(t, err)
		assert.True(t, match)
	})

	t.Run("Failure: Compare with invalid hash formats", func(t *testing.T) {
		hasher := NewArgo2Hasher(nil)
		testCases := []struct {
			name string
			hash string
			err  error
		}{
			{"empty hash", "", ErrInvalidHashFormat},
			{"too few parts", "$argon2id$v=19$m=65536,t=1,p=4$c29tZXNhbHQ", ErrInvalidHashFormat},
			{"malformed params", "$argon2id$v=19$m=65536,t=1$%s$%s", ErrInvalidHashFormat},
			{"invalid base64 salt", "$argon2id$v=19$m=65536,t=1,p=4$not-b64$somehash", ErrInvalidHashFormat},
			{"invalid base64 hash", "$argon2id$v=19$m=65536,t=1,p=4$c29tZXNhbHQ$not-b64", ErrInvalidHashFormat},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				match, err := hasher.Compare(password, tc.hash)
				assert.ErrorIs(t, err, tc.err)
				assert.False(t, match)
			})
		}
	})

	t.Run("Failure: Compare with incompatible version", func(t *testing.T) {
		hasher := NewArgo2Hasher(nil)
		// Manually create a hash with a future version number
		incompatibleHash := fmt.Sprintf(
			"$argon2id$v=%d$m=65536,t=1,p=4$c29tZXNhbHQ$somehash",
			argon2.Version+1,
		)

		match, err := hasher.Compare(password, incompatibleHash)
		assert.ErrorIs(t, err, ErrIncompatibleVersion)
		assert.False(t, match)
	})
}
