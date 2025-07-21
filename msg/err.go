package msg

import (
	"fmt"
	"net/http"
)

type ErrorCode string

const (
	CodeConflict        ErrorCode = "conflict"
	CodeInvalid         ErrorCode = "invalid_input"
	CodeNotFound        ErrorCode = "not_found"
	CodeInternal        ErrorCode = "internal_error"
	CodeUnauthorized    ErrorCode = "unauthorized"
	CodeForbidden       ErrorCode = "forbidden"
	CodeDomainViolation ErrorCode = "domain_violation"
)

type MessageError struct {
	Err     error
	Message string
	Code    ErrorCode
	Context map[string]any
	Details []*MessageError
}

func (e *MessageError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *MessageError) Unwrap() error {
	return e.Err
}

func (e *MessageError) WithContext(key string, value any) *MessageError {
	if e.Context == nil {
		e.Context = make(map[string]any)
	}
	e.Context[key] = value
	return e
}

func NewMessageError(err error, message string, code ErrorCode, context map[string]any) *MessageError {
	return &MessageError{
		Err:     err,
		Message: message,
		Code:    code,
		Context: context,
	}
}

func NewDomainError(err error, message string, context map[string]any) *MessageError {
	return &MessageError{
		Err:     err,
		Message: message,
		Code:    CodeDomainViolation,
		Context: context,
	}
}

// --- Constructors for common error types ---

func NewValidationError(err error, context map[string]any, message string) *MessageError {
	return NewMessageError(err, message, CodeInvalid, context)
}

func NewBadRequestError(err error, context map[string]any) *MessageError {
	return NewMessageError(err, "The request is malformed or contains invalid parameters.", CodeInvalid, context)
}

func NewInternalError(err error, context map[string]any) *MessageError {
	return NewMessageError(err, "An unexpected internal error occurred.", CodeInternal, context)
}

func NewUnauthorizedError(err error, context map[string]any) *MessageError {
	return NewMessageError(err, "You are not authorized to perform this action.", CodeUnauthorized, context)
}

func NewForbiddenError(err error, context map[string]any) *MessageError {
	return NewMessageError(err, "You do not have permission to perform this action.", CodeForbidden, context)
}

type ErrorResponse struct {
	StatusCode int             `json:"-"`
	Message    string          `json:"message"`
	Code       string          `json:"code,omitempty"`
	Context    map[string]any  `json:"context,omitempty"`
	Details    []ErrorResponse `json:"details,omitempty"`
}

func (e *MessageError) ToResponse() ErrorResponse {
	resp := ErrorResponse{
		StatusCode: e.HTTPStatus(),
		Message:    e.Message,
		Code:       string(e.Code),
		Context:    e.Context,
	}
	for _, detail := range e.Details {
		resp.Details = append(resp.Details, detail.ToResponse())
	}
	return resp
}

func (e *MessageError) HTTPStatus() int {
	switch e.Code {
	case CodeConflict:
		return http.StatusConflict
	case CodeInvalid:
		return http.StatusBadRequest
	case CodeNotFound:
		return http.StatusNotFound
	case CodeUnauthorized:
		return http.StatusUnauthorized
	case CodeForbidden:
		return http.StatusForbidden
	case CodeInternal:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}
