package doberman_test

import (
	"encoding/json"
	"errors"
	"regexp"
	"testing"

	"github.com/marcelofabianov/fault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/marcelofabianov/doberman"
)

var (
	testHasNumberRegex = regexp.MustCompile(`[0-9]`)
	testHasUpperRegex  = regexp.MustCompile(`[A-Z]`)
	testHasLowerRegex  = regexp.MustCompile(`[a-z]`)
	testHasSymbolRegex = regexp.MustCompile(`[^a-zA-Z0-9]`)
)

func TestPasswordValidator_Generate(t *testing.T) {
	t.Run("with default config", func(t *testing.T) {
		validator := doberman.NewPasswordValidator(nil)
		password, err := validator.Generate()
		require.Nil(t, err)

		passStr := password.String()
		assert.Len(t, passStr, doberman.DefaultPasswordConfig.MinLength)
		assert.True(t, testHasNumberRegex.MatchString(passStr), "should have a number")
		assert.True(t, testHasUpperRegex.MatchString(passStr), "should have an uppercase letter")
		assert.True(t, testHasLowerRegex.MatchString(passStr), "should have a lowercase letter")
		assert.True(t, testHasSymbolRegex.MatchString(passStr), "should have a symbol")
	})

	t.Run("with custom config requiring only some types", func(t *testing.T) {
		config := &doberman.PasswordConfig{
			MinLength:     20,
			RequireNumber: true,
			RequireUpper:  false,
			RequireLower:  true,
			RequireSymbol: false,
		}
		validator := doberman.NewPasswordValidator(config)
		password, err := validator.Generate()
		require.Nil(t, err)

		passStr := password.String()
		assert.Len(t, passStr, config.MinLength)
		assert.True(t, testHasNumberRegex.MatchString(passStr), "should have a number because it is required")
		assert.True(t, testHasLowerRegex.MatchString(passStr), "should have a lowercase letter because it is required")
	})

	t.Run("with custom config requiring no types", func(t *testing.T) {
		config := &doberman.PasswordConfig{
			MinLength:     15,
			RequireNumber: false,
			RequireUpper:  false,
			RequireLower:  false,
			RequireSymbol: false,
		}
		validator := doberman.NewPasswordValidator(config)

		assert.NotPanics(t, func() {
			password, err := validator.Generate()
			require.Nil(t, err)
			assert.Len(t, password.String(), config.MinLength)
		})
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
		{name: "too short", password: "Sh0rt!", expectError: true, errorMsg: "at least 10 characters long", errorCode: fault.Invalid},
		{name: "no number", password: "NoNumberPass!", expectError: true, errorMsg: "numeric character", errorCode: fault.Invalid},
		{name: "no uppercase", password: "noupperc@se1", expectError: true, errorMsg: "uppercase letter", errorCode: fault.Invalid},
		{name: "no lowercase", password: "NOLOWERC@SE1", expectError: true, errorMsg: "lowercase letter", errorCode: fault.Invalid},
		{name: "no symbol", password: "NoSymbolPass1", expectError: true, errorMsg: "one symbol", errorCode: fault.Invalid},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.Validate(tc.password)
			if tc.expectError {
				require.NotNil(t, err)
				assert.Contains(t, err.Message, tc.errorMsg)
				assert.Equal(t, tc.errorCode, err.Code)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestNewPassword_DefaultValidator(t *testing.T) {
	p, err := doberman.NewPassword("DefaultV@lid1")
	require.Nil(t, err)
	assert.Equal(t, "DefaultV@lid1", p.String())

	_, err = doberman.NewPassword("invalid")
	require.NotNil(t, err)
	assert.Equal(t, fault.Invalid, err.Code)
}

func TestMustNewPassword(t *testing.T) {
	assert.NotPanics(t, func() {
		p := doberman.MustNewPassword("MustBeV@lid1")
		assert.Equal(t, "MustBeV@lid1", p.String())
	})

	assert.Panics(t, func() {
		doberman.MustNewPassword("invalid")
	})
}

func TestPassword_JSON(t *testing.T) {
	t.Run("marshal", func(t *testing.T) {
		p, err := doberman.NewPassword("JSONP@ssw0rd!")
		require.Nil(t, err)
		jsonData, jsonErr := json.Marshal(p)
		require.NoError(t, jsonErr)
		assert.Equal(t, `"JSONP@ssw0rd!"`, string(jsonData))
	})

	t.Run("unmarshal success", func(t *testing.T) {
		var unmarshaledP doberman.Password
		err := json.Unmarshal([]byte(`"ValidUnm@rsh1"`), &unmarshaledP)
		require.NoError(t, err)
		assert.Equal(t, doberman.Password("ValidUnm@rsh1"), unmarshaledP)
	})

	t.Run("unmarshal failure on invalid json", func(t *testing.T) {
		var unmarshaledP doberman.Password
		err := json.Unmarshal([]byte(`not-a-string`), &unmarshaledP)
		require.Error(t, err)
		t.Logf("Error type: %T, value: %v", err, err)
		var syntaxErr *json.SyntaxError
		var faultErr *fault.Error
		if errors.As(err, &syntaxErr) {
			// JSON syntax error is acceptable for invalid JSON input
			assert.Contains(t, err.Error(), "invalid character")
		} else if errors.As(err, &faultErr) {
			assert.Equal(t, fault.Invalid, faultErr.Code)
			assert.Contains(t, faultErr.Message, "password must be a valid JSON string")
		} else {
			t.Fatalf("error should be *json.SyntaxError or *fault.Error, got %T: %v", err, err)
		}
	})

	t.Run("unmarshal failure on invalid password policy", func(t *testing.T) {
		var unmarshaledP doberman.Password
		err := json.Unmarshal([]byte(`"invalid"`), &unmarshaledP)
		require.Error(t, err)
		faultErr, ok := err.(*fault.Error)
		require.True(t, ok, "error should be of type *fault.Error")
		assert.Equal(t, fault.Invalid, faultErr.Code)
		assert.Contains(t, faultErr.Message, "at least 10 characters long")
	})
}

func TestPassword_Database(t *testing.T) {
	t.Run("value", func(t *testing.T) {
		p, err := doberman.NewPassword("DatabaseP@ss1")
		require.Nil(t, err)
		val, valErr := p.Value()
		require.NoError(t, valErr)
		assert.Equal(t, "DatabaseP@ss1", val)
	})

	t.Run("scan success", func(t *testing.T) {
		var scannedP doberman.Password
		err := scannedP.Scan("ScannedP@ssw1")
		require.NoError(t, err)
		assert.Equal(t, doberman.Password("ScannedP@ssw1"), scannedP)
	})

	t.Run("scan failure on invalid password policy", func(t *testing.T) {
		var scannedP doberman.Password
		err := scannedP.Scan("invalid")
		require.Error(t, err)
		faultErr, ok := err.(*fault.Error)
		require.True(t, ok, "error should be of type *fault.Error")
		assert.Equal(t, fault.Invalid, faultErr.Code)
	})

	t.Run("scan failure on incompatible type", func(t *testing.T) {
		var scannedP doberman.Password
		err := scannedP.Scan(12345)
		require.Error(t, err)
		faultErr, ok := err.(*fault.Error)
		require.True(t, ok, "error should be of type *fault.Error")
		assert.Equal(t, fault.Internal, faultErr.Code)
	})
}

func TestPassword_UnmarshalJSON_Direct(t *testing.T) {
	t.Run("invalid json string", func(t *testing.T) {
		var p doberman.Password
		err := p.UnmarshalJSON([]byte(`"invalid"`))
		require.Error(t, err)
		t.Logf("Error type: %T, value: %v", err, err)
		var faultErr *fault.Error
		require.True(t, errors.As(err, &faultErr), "error should be or wrap a *fault.Error")
		assert.Equal(t, fault.Invalid, faultErr.Code)
		assert.Contains(t, faultErr.Message, "password must be at least 10 characters long")
	})

	t.Run("valid json string", func(t *testing.T) {
		var p doberman.Password
		err := p.UnmarshalJSON([]byte(`"ValidP@ss10"`))
		require.NoError(t, err)
		assert.Equal(t, doberman.Password("ValidP@ss10"), p)
	})
}
