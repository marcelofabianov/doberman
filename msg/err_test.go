package msg

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMessageError(t *testing.T) {
	originalErr := errors.New("original error")
	context := map[string]any{"key1": "value1"}
	message := "user message"
	code := CodeInvalid

	err := NewMessageError(originalErr, message, code, context)

	require.NotNil(t, err, "NewMessageError should not return nil")
	assert.Equal(t, originalErr, err.Err)
	assert.Equal(t, message, err.Message)
	assert.Equal(t, code, err.Code)
	assert.Equal(t, context, err.Context)

	errNoContext := NewMessageError(nil, "another message", CodeInternal, nil)
	assert.Nil(t, errNoContext.Context, "Context should be nil if input context is nil")
}

func TestMessageError_ErrorMethod(t *testing.T) {
	tests := []struct {
		name          string
		errInstance   *MessageError
		expectedError string
	}{
		{"Error with Message and Original Error", &MessageError{Message: "user message", Err: errors.New("original")}, "user message: original"},
		{"Error with only Message", &MessageError{Message: "user message", Err: nil}, "user message"},
		{"Error with empty Message but with Original Error", &MessageError{Message: "", Err: errors.New("original")}, ": original"},
		{"Error with no fields", &MessageError{}, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedError, tc.errInstance.Error())
		})
	}
}

func TestMessageError_Unwrap(t *testing.T) {
	originalErr := errors.New("original")
	errWithOriginal := NewMessageError(originalErr, "msg", CodeInternal, nil)
	errWithoutOriginal := NewMessageError(nil, "msg", CodeInternal, nil)

	assert.Equal(t, originalErr, errWithOriginal.Unwrap())
	assert.True(t, errors.Is(errWithOriginal, originalErr))
	assert.Nil(t, errWithoutOriginal.Unwrap())
}

func TestMessageError_WithContext(t *testing.T) {
	err := NewMessageError(nil, "initial message", CodeInvalid, nil)
	require.Nil(t, err.Context, "Initial context should be nil")

	err.WithContext("key1", "value1")
	assert.Equal(t, map[string]any{"key1": "value1"}, err.Context)

	err.WithContext("key2", 123)
	expectedCtx1 := map[string]any{"key1": "value1", "key2": 123}
	assert.Equal(t, expectedCtx1, err.Context)

	returnedErr := err.WithContext("key1", "newValue1")
	assert.Same(t, err, returnedErr, "WithContext should return the same error instance for chaining")
}

func TestMessageError_HTTPStatus(t *testing.T) {
	testCases := []struct {
		name           string
		code           ErrorCode
		expectedStatus int
	}{
		{"Conflict", CodeConflict, http.StatusConflict},
		{"Invalid Input", CodeInvalid, http.StatusBadRequest},
		{"Not Found", CodeNotFound, http.StatusNotFound},
		{"Internal Error", CodeInternal, http.StatusInternalServerError},
		{"Unauthorized", CodeUnauthorized, http.StatusUnauthorized},
		{"Forbidden", CodeForbidden, http.StatusForbidden},
		{"Unknown Code", ErrorCode("SOME_NEW_CODE"), http.StatusInternalServerError},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := NewMessageError(nil, "test", tc.code, nil)
			assert.Equal(t, tc.expectedStatus, err.HTTPStatus())
		})
	}
}

func TestMessageError_ToResponse(t *testing.T) {
	t.Run("converts a simple error correctly", func(t *testing.T) {
		err := NewMessageError(
			errors.New("db connection failed"),
			"Could not process request",
			CodeInternal,
			map[string]any{"request_id": "abc-123"},
		)

		response := err.ToResponse()

		assert.Equal(t, http.StatusInternalServerError, response.StatusCode)
		assert.Equal(t, "Could not process request", response.Message)
		assert.Equal(t, string(CodeInternal), response.Code)
		assert.Equal(t, map[string]any{"request_id": "abc-123"}, response.Context)
		assert.Empty(t, response.Details, "Details should be empty for a simple error")
	})

	t.Run("converts an error with details correctly", func(t *testing.T) {
		detail1 := NewValidationError(nil, map[string]any{"field": "email"}, "must be a valid email")
		detail2 := NewValidationError(nil, map[string]any{"field": "password"}, "must be at least 10 chars")

		parentErr := &MessageError{
			Err:     errors.New("validation failed"),
			Message: "One or more fields are invalid",
			Code:    CodeInvalid,
			Context: map[string]any{"form": "registration"},
			Details: []*MessageError{detail1, detail2},
		}

		response := parentErr.ToResponse()

		assert.Equal(t, http.StatusBadRequest, response.StatusCode)
		assert.Equal(t, "One or more fields are invalid", response.Message)
		assert.Equal(t, string(CodeInvalid), response.Code)
		assert.Equal(t, map[string]any{"form": "registration"}, response.Context)
		require.Len(t, response.Details, 2, "Should have two detail items")

		assert.Equal(t, "must be a valid email", response.Details[0].Message)
		assert.Equal(t, string(CodeInvalid), response.Details[0].Code)
		assert.Equal(t, map[string]any{"field": "email"}, response.Details[0].Context)

		assert.Equal(t, "must be at least 10 chars", response.Details[1].Message)
		assert.Equal(t, string(CodeInvalid), response.Details[1].Code)
		assert.Equal(t, map[string]any{"field": "password"}, response.Details[1].Context)
	})
}
