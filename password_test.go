package doberman_test

import (
	"testing"

	"github.com/marcelofabianov/fault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/marcelofabianov/doberman"
)

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
