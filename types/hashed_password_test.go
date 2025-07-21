package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashedPassword_Behaviors(t *testing.T) {
	t.Run("Constructor and Basic Methods", func(t *testing.T) {
		hashStr := "a-valid-hash-string"
		hp := NewHashedPassword(hashStr)

		assert.Equal(t, hashStr, hp.String())
		assert.False(t, hp.IsEmpty())

		emptyHp := NewHashedPassword("")
		assert.True(t, emptyHp.IsEmpty())
	})
}

func TestHashedPassword_Integrations(t *testing.T) {
	hashStr := "$argon2id$v=19$m=65536,t=1,p=4$c29tZXNhbHQ$somehash"

	t.Run("JSON Marshaling and Unmarshaling", func(t *testing.T) {
		hp := NewHashedPassword(hashStr)

		jsonData, err := json.Marshal(hp)
		require.NoError(t, err)
		assert.JSONEq(t, `"`+hashStr+`"`, string(jsonData))

		var unmarshaledHP HashedPassword
		err = json.Unmarshal(jsonData, &unmarshaledHP)
		require.NoError(t, err)
		assert.Equal(t, hp, unmarshaledHP)
	})

	t.Run("JSON Unmarshal failure with malformed JSON", func(t *testing.T) {
		invalidJSON := []byte(`not-a-json-string`)
		var hp HashedPassword
		err := json.Unmarshal(invalidJSON, &hp)
		assert.Error(t, err)
	})

	t.Run("Database Scan and Value", func(t *testing.T) {
		hp := NewHashedPassword(hashStr)

		val, err := hp.Value()
		require.NoError(t, err)
		assert.Equal(t, hashStr, val)

		var scannedHP HashedPassword
		err = scannedHP.Scan(val)
		require.NoError(t, err)
		assert.Equal(t, hp, scannedHP)
	})

	t.Run("Database Scan from different source types", func(t *testing.T) {
		var hpFromBytes HashedPassword
		err := hpFromBytes.Scan([]byte(hashStr))
		require.NoError(t, err)
		assert.Equal(t, hashStr, hpFromBytes.String())

		var hpFromNil HashedPassword
		err = hpFromNil.Scan(nil)
		require.NoError(t, err)
		assert.True(t, hpFromNil.IsEmpty())
	})

	t.Run("Database Scan failure with incompatible type", func(t *testing.T) {
		var hp HashedPassword
		err := hp.Scan(12345)
		assert.Error(t, err)
	})

	t.Run("Database Value from empty HashedPassword", func(t *testing.T) {
		var hp HashedPassword
		val, err := hp.Value()
		require.NoError(t, err)
		assert.Nil(t, val)
	})
}
