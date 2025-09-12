package doberman_test

import (
	"encoding/json"
	"testing"

	"github.com/marcelofabianov/fault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/marcelofabianov/doberman"
)

func TestNewPasswordValidator(t *testing.T) {
	t.Run("should use default config when nil is provided", func(t *testing.T) {
		validator := doberman.NewPasswordValidator(nil)
		err := validator.Validate("short")
		require.Error(t, err)
		faultErr, ok := err.(*fault.Error)
		require.True(t, ok)
		assert.Contains(t, faultErr.Message, "at least 10 characters long")
	})

	t.Run("should use the provided custom config", func(t *testing.T) {
		customConfig := &doberman.PasswordConfig{
			MinLength:     5,
			RequireNumber: false,
			RequireUpper:  false,
			RequireLower:  false,
			RequireSymbol: false,
		}
		validator := doberman.NewPasswordValidator(customConfig)

		assert.NoError(t, validator.Validate("valid"))
		assert.NoError(t, validator.Validate("abcde"))

		err := validator.Validate("four")
		require.Error(t, err)
		faultErr, ok := err.(*fault.Error)
		require.True(t, ok)
		assert.Contains(t, faultErr.Message, "at least 5 characters long")
	})
}

func TestPasswordValidator_Validate(t *testing.T) {
	validator := doberman.NewPasswordValidator(doberman.DefaultPasswordConfig)

	testCases := []struct {
		name        string
		password    string
		expectError bool
		errorMsg    string
		errorCode   fault.Code
	}{
		{name: "valid password", password: "ValidP@ss10", expectError: false},
		{name: "empty password", password: "", expectError: true, errorMsg: "password cannot be empty", errorCode: fault.Invalid},
		{name: "too short", password: "Sh0rt!", expectError: true, errorMsg: "password must be at least 10 characters long", errorCode: fault.Invalid},
		{name: "no number", password: "NoNumberPass!", expectError: true, errorMsg: "password must contain at least one numeric character", errorCode: fault.Invalid},
		{name: "no uppercase", password: "noupperc@se1", expectError: true, errorMsg: "password must contain at least one uppercase letter", errorCode: fault.Invalid},
		{name: "no lowercase", password: "NOLOWERC@SE1", expectError: true, errorMsg: "password must contain at least one lowercase letter", errorCode: fault.Invalid},
		{name: "no symbol", password: "NoSymbolPass1", expectError: true, errorMsg: "password must contain at least one symbol", errorCode: fault.Invalid},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.Validate(tc.password)
			if tc.expectError {
				require.Error(t, err)
				faultErr, ok := err.(*fault.Error)
				require.True(t, ok)
				assert.Contains(t, faultErr.Message, tc.errorMsg)
				assert.Equal(t, tc.errorCode, faultErr.Code)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPasswordValidator_NewPassword(t *testing.T) {
	validator := doberman.NewPasswordValidator(doberman.DefaultPasswordConfig)

	t.Run("should create password successfully with valid input", func(t *testing.T) {
		p, err := validator.NewPassword("ValidP@ssw0rd")
		require.NoError(t, err)
		assert.Equal(t, doberman.Password("ValidP@ssw0rd"), p)
	})

	t.Run("should return error with invalid input", func(t *testing.T) {
		p, err := validator.NewPassword("invalid")
		require.Error(t, err)
		assert.True(t, p.IsEmpty(), "password should be empty on failure")
		faultErr, ok := err.(*fault.Error)
		require.True(t, ok)
		assert.Equal(t, fault.Invalid, faultErr.Code)
	})
}

func TestPassword_Lifecycle(t *testing.T) {
	t.Run("NewPassword using default validator", func(t *testing.T) {
		p, err := doberman.NewPassword("DefaultV@lid1")
		require.NoError(t, err)
		assert.Equal(t, "DefaultV@lid1", p.String())

		_, err = doberman.NewPassword("invalid")
		require.Error(t, err)
		faultErr, ok := err.(*fault.Error)
		require.True(t, ok)
		assert.Equal(t, fault.Invalid, faultErr.Code)
	})

	t.Run("MustNewPassword", func(t *testing.T) {
		assert.NotPanics(t, func() {
			p := doberman.MustNewPassword("MustBeV@lid1")
			assert.Equal(t, "MustBeV@lid1", p.String())
		})

		assert.Panics(t, func() {
			doberman.MustNewPassword("invalid")
		})
	})

	t.Run("IsEmpty", func(t *testing.T) {
		p := doberman.MustNewPassword("ValidP@ssw0rd1")
		assert.False(t, p.IsEmpty())

		var emptyP doberman.Password
		assert.True(t, emptyP.IsEmpty())
	})

	t.Run("String", func(t *testing.T) {
		p := doberman.MustNewPassword("ValidP@ssw0rd1")
		assert.Equal(t, "ValidP@ssw0rd1", p.String())
	})
}

func TestPassword_JSON(t *testing.T) {
	t.Run("MarshalJSON should return redacted string", func(t *testing.T) {
		p := doberman.MustNewPassword("MyS3cretP@ss!")
		bytes, err := json.Marshal(p)
		require.NoError(t, err)
		assert.Equal(t, `"[REDACTED]"`, string(bytes))
	})

	t.Run("UnmarshalJSON", func(t *testing.T) {
		t.Run("should succeed with valid password", func(t *testing.T) {
			var p doberman.Password
			jsonStr := `"ValidUnm@rshal1"`
			err := json.Unmarshal([]byte(jsonStr), &p)
			require.NoError(t, err)
			assert.Equal(t, doberman.Password("ValidUnm@rshal1"), p)
		})

		t.Run("should fail on invalid password policy", func(t *testing.T) {
			var p doberman.Password
			jsonStr := `"invalid"`
			err := json.Unmarshal([]byte(jsonStr), &p)
			require.Error(t, err)
			faultErr, ok := err.(*fault.Error)
			require.True(t, ok)
			assert.Equal(t, fault.Invalid, faultErr.Code)
		})

		t.Run("should fail on invalid json type", func(t *testing.T) {
			var p doberman.Password
			jsonNum := `12345`
			err := json.Unmarshal([]byte(jsonNum), &p)
			require.Error(t, err)
			faultErr, ok := err.(*fault.Error)
			require.True(t, ok)
			assert.Equal(t, fault.Invalid, faultErr.Code)
			assert.Contains(t, faultErr.Error(), "password must be a valid JSON string")
		})
	})
}

func TestPassword_Database(t *testing.T) {
	t.Run("Value", func(t *testing.T) {
		t.Run("should return string for non-empty password", func(t *testing.T) {
			p := doberman.MustNewPassword("DbValu@bleP@ss1")
			val, err := p.Value()
			require.NoError(t, err)
			assert.Equal(t, "DbValu@bleP@ss1", val)
		})

		t.Run("should return nil for empty password", func(t *testing.T) {
			var p doberman.Password
			val, err := p.Value()
			require.NoError(t, err)
			assert.Nil(t, val)
		})
	})

	t.Run("Scan", func(t *testing.T) {
		testCases := []struct {
			name     string
			source   interface{}
			expected doberman.Password
		}{
			{name: "from string", source: "ScannedP@ssw1", expected: "ScannedP@ssw1"},
			{name: "from byte slice", source: []byte("ScannedP@ssw2"), expected: "ScannedP@ssw2"},
			{name: "from nil", source: nil, expected: ""},
		}

		for _, tc := range testCases {
			t.Run("should succeed "+tc.name, func(t *testing.T) {
				var p doberman.Password
				err := p.Scan(tc.source)
				require.NoError(t, err)
				assert.Equal(t, tc.expected, p)
			})
		}

		t.Run("should fail on invalid password policy", func(t *testing.T) {
			var p doberman.Password
			err := p.Scan("invalid")
			require.Error(t, err)
			faultErr, ok := err.(*fault.Error)
			require.True(t, ok)
			assert.Equal(t, fault.Invalid, faultErr.Code)
		})

		t.Run("should fail on incompatible type", func(t *testing.T) {
			var p doberman.Password
			err := p.Scan(12345)
			require.Error(t, err)
			faultErr, ok := err.(*fault.Error)
			require.True(t, ok)
			assert.Equal(t, fault.Internal, faultErr.Code)
			assert.Contains(t, faultErr.Message, "incompatible type (int) for password scan")
		})
	})
}
