// types/password_test.go
package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordValidator_Validate(t *testing.T) {
	tests := []struct {
		name      string
		config    *PasswordConfig
		password  string
		expectErr bool
	}{
		{
			name:      "Success: Default config with valid password",
			config:    nil, // Uses DefaultPasswordConfig
			password:  "ValidPass123!",
			expectErr: false,
		},
		{
			name:      "Failure: Default config, too short",
			config:    nil,
			password:  "Vp1!",
			expectErr: true,
		},
		{
			name:      "Failure: Default config, missing number",
			config:    nil,
			password:  "ValidPassword!",
			expectErr: true,
		},
		{
			name:      "Failure: Default config, missing uppercase",
			config:    nil,
			password:  "validpass123!",
			expectErr: true,
		},
		{
			name:      "Failure: Default config, missing lowercase",
			config:    nil,
			password:  "VALIDPASS123!",
			expectErr: true,
		},
		{
			name:      "Failure: Default config, missing symbol",
			config:    nil,
			password:  "ValidPass123",
			expectErr: true,
		},
		{
			name:      "Failure: Empty password",
			config:    nil,
			password:  "",
			expectErr: true,
		},
		{
			name: "Success: Custom simple config with valid password",
			config: &PasswordConfig{
				MinLength:     8,
				RequireNumber: true,
				RequireLower:  true,
			},
			password:  "simple123",
			expectErr: false,
		},
		{
			name: "Failure: Custom simple config with invalid password",
			config: &PasswordConfig{
				MinLength:     8,
				RequireNumber: true,
				RequireLower:  true,
			},
			password:  "justletters",
			expectErr: true,
		},
		{
			name: "Success: Custom config allows no symbols",
			config: &PasswordConfig{
				MinLength:     10,
				RequireNumber: true,
				RequireUpper:  true,
				RequireLower:  true,
				RequireSymbol: false,
			},
			password:  "NoSymbolsNeeded1",
			expectErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			validator := NewPasswordValidator(tc.config)
			err := validator.Validate(tc.password)

			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPasswordValidator_Generate(t *testing.T) {
	configs := map[string]*PasswordConfig{
		"Default": DefaultPasswordConfig,
		"Simple": {
			MinLength:     8,
			RequireNumber: true,
			RequireLower:  true,
		},
		"Complex_No_Symbols": {
			MinLength:     20,
			RequireNumber: true,
			RequireUpper:  true,
			RequireLower:  true,
			RequireSymbol: false,
		},
		"Only_Symbols_And_Numbers": {
			MinLength:     15,
			RequireNumber: true,
			RequireSymbol: true,
		},
	}

	for name, config := range configs {
		t.Run(name, func(t *testing.T) {
			validator := NewPasswordValidator(config)
			generatedPassword, err := validator.Generate()

			require.NoError(t, err, "Generate() should not produce an error")
			require.False(t, generatedPassword.IsEmpty(), "Generated password should not be empty")

			err = validator.Validate(generatedPassword.String())
			assert.NoError(t, err, "Generated password must be valid according to its own validator")
		})
	}
}

func TestPassword_Integrations(t *testing.T) {
	t.Run("JSON Marshaling and Unmarshaling", func(t *testing.T) {
		p, err := NewPassword("ValidPass123!")
		require.NoError(t, err)

		jsonData, err := json.Marshal(p)
		require.NoError(t, err)
		assert.JSONEq(t, `"ValidPass123!"`, string(jsonData))

		var unmarshaledP Password
		err = json.Unmarshal(jsonData, &unmarshaledP)
		require.NoError(t, err)
		assert.Equal(t, p, unmarshaledP)
	})

	t.Run("JSON Unmarshal failure with invalid password", func(t *testing.T) {
		invalidJSON := []byte(`"invalid"`)
		var p Password
		err := json.Unmarshal(invalidJSON, &p)
		assert.Error(t, err)
	})

	t.Run("Database Scan and Value", func(t *testing.T) {
		p, err := NewPassword("ValidPass123!")
		require.NoError(t, err)

		val, err := p.Value()
		require.NoError(t, err)
		assert.Equal(t, "ValidPass123!", val)

		var scannedP Password
		err = scannedP.Scan(val)
		require.NoError(t, err)
		assert.Equal(t, p, scannedP)
	})

	t.Run("Database Scan from nil", func(t *testing.T) {
		var p Password
		err := p.Scan(nil)
		require.NoError(t, err)
		assert.True(t, p.IsEmpty())
	})

	t.Run("Database Value from empty password", func(t *testing.T) {
		var p Password
		val, err := p.Value()
		require.NoError(t, err)
		assert.Nil(t, val)
	})
}

