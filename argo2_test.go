package doberman_test

import (
	"fmt"
	"testing"

	"github.com/marcelofabianov/doberman"
	"github.com/marcelofabianov/fault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArgo2Hasher_HashAndCompare(t *testing.T) {
	hasher := doberman.NewArgo2Hasher(nil)
	password, err := doberman.NewPassword("S3cureP@ssw0rd!")
	require.NoError(t, err)

	// Test Hash
	hashedPassword, faultErr := hasher.Hash(password)
	require.Nil(t, faultErr)
	assert.NotEmpty(t, hashedPassword)
	assert.Contains(t, hashedPassword.String(), "$argon2id$")

	// Test Compare - Success
	err = hasher.Compare(password, hashedPassword)
	require.NoError(t, err)

	// Test Compare - Failure (wrong password)
	wrongPassword, err := doberman.NewPassword("WrongP@ssw0rd!")
	require.NoError(t, err)

	err = hasher.Compare(wrongPassword, hashedPassword)
	require.Error(t, err)
	assert.ErrorIs(t, err, doberman.ErrMismatch)

	// Para verificar o código do erro, precisamos fazer o type assertion
	fErr, ok := fault.AsFault(err)
	require.True(t, ok)
	assert.Equal(t, fault.Unauthorized, fErr.Code)
}

func TestArgo2Hasher_Compare_InvalidFormat(t *testing.T) {
	hasher := doberman.NewArgo2Hasher(nil)
	password, err := doberman.NewPassword("S3cureP@ssw0rd!")
	require.NoError(t, err)

	testCases := []struct {
		name          string
		hashed        doberman.HashedPassword
		expectedMsg   string
		expectedCode  fault.Code
		assertVersion bool
	}{
		{
			name:         "invalid number of parts",
			hashed:       doberman.HashedPassword("$argon2id$v=19$m=65536,t=1,p=4$salt"),
			expectedMsg:  "invalid hash format",
			expectedCode: fault.Internal,
		},
		{
			name:          "incompatible version",
			hashed:        doberman.HashedPassword("$argon2id$v=18$m=65536,t=1,p=4$c2FsdHNhbHRzYWx0$aGFzaA=="),
			expectedMsg:   "incompatible argon2 version",
			expectedCode:  fault.Internal,
			assertVersion: true,
		},
		{
			name:         "malformed params",
			hashed:       doberman.HashedPassword("$argon2id$v=19$m=65536,t=1$c2FsdHNhbHRzYWx0$aGFzaA=="),
			expectedMsg:  "could not parse argon2 params from hash",
			expectedCode: fault.Internal,
		},
		{
			name:         "invalid salt encoding",
			hashed:       doberman.HashedPassword("$argon2id$v=19$m=65536,t=1,p=4$invalid-salt$aGFzaA=="),
			expectedMsg:  "could not decode salt from hash",
			expectedCode: fault.Internal,
		},
		{
			name:         "invalid hash encoding",
			hashed:       doberman.HashedPassword("$argon2id$v=19$m=65536,t=1,p=4$c2FsdHNhbHRzYWx0$invalid-hash"),
			expectedMsg:  "could not decode hash part from encoded string",
			expectedCode: fault.Internal,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := hasher.Compare(password, tc.hashed)
			require.Error(t, err)

			fErr, ok := fault.AsFault(err)
			require.True(t, ok, "error must be of type *fault.Error")

			assert.Contains(t, fErr.Message, tc.expectedMsg)
			assert.Equal(t, tc.expectedCode, fErr.Code)

			if tc.assertVersion {
				ctx := fErr.Context
				require.NotNil(t, ctx)
				assert.Contains(t, ctx, "expected_version")
				assert.Contains(t, ctx, "actual_version")
			}
		})
	}
}

func TestNewArgo2Hasher_WithCustomConfig(t *testing.T) {
	customConfig := &doberman.Config{
		Time:        2,
		Memory:      128 * 1024,
		Parallelism: 2,
		SaltLength:  32,
		KeyLength:   64,
	}
	hasher := doberman.NewArgo2Hasher(customConfig)
	password, err := doberman.NewPassword("TestWithCustomC0nfig!")
	require.NoError(t, err)

	hashed, faultErr := hasher.Hash(password)
	require.Nil(t, faultErr)

	expectedParams := fmt.Sprintf("m=%d,t=%d,p=%d", customConfig.Memory, customConfig.Time, customConfig.Parallelism)
	assert.Contains(t, string(hashed), expectedParams)

	err = hasher.Compare(password, hashed)
	require.NoError(t, err)
}
