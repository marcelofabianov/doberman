package doberman_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/marcelofabianov/doberman"
)

func TestHashedPassword_IsEmpty(t *testing.T) {
	var hp doberman.HashedPassword
	assert.True(t, hp.IsEmpty())

	hp = "not-empty"
	assert.False(t, hp.IsEmpty())
}

func TestHashedPassword_JSON(t *testing.T) {
	// Test Marshal
	hp := doberman.NewHashedPassword("my-hashed-password")
	jsonData, err := json.Marshal(hp)
	require.NoError(t, err)
	assert.Equal(t, `"my-hashed-password"`, string(jsonData))

	// Test Unmarshal - Success
	var unmarshaledHp doberman.HashedPassword
	err = json.Unmarshal([]byte(`"a-new-hash"`), &unmarshaledHp)
	require.NoError(t, err)
	assert.Equal(t, doberman.HashedPassword("a-new-hash"), unmarshaledHp)

	// Test Unmarshal - Failure (invalid type)
	err = json.Unmarshal([]byte(`12345`), &unmarshaledHp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HashedPassword must be a valid JSON string")
}

func TestHashedPassword_Database(t *testing.T) {
	// Test Value - Success
	hp := doberman.NewHashedPassword("db-hash")
	val, err := hp.Value()
	require.NoError(t, err)
	assert.Equal(t, "db-hash", val.(string))

	// Test Value - Empty
	var emptyHp doberman.HashedPassword
	val, err = emptyHp.Value()
	require.NoError(t, err)
	assert.Nil(t, val)

	// Test Scan
	testCases := []struct {
		name     string
		src      interface{}
		expected doberman.HashedPassword
		hasError bool
	}{
		{name: "scan string", src: "scanned-hash", expected: "scanned-hash", hasError: false},
		{name: "scan bytes", src: []byte("scanned-bytes-hash"), expected: "scanned-bytes-hash", hasError: false},
		{name: "scan nil", src: nil, expected: "", hasError: false},
		{name: "scan incompatible type", src: 12345, expected: "", hasError: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var scannedHp doberman.HashedPassword
			err := scannedHp.Scan(tc.src)

			if tc.hasError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "incompatible type")
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, scannedHp)
			}
		})
	}
}
