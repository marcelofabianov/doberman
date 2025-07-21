package types

import (
	"crypto/rand"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"unicode/utf8"

	"github.com/marcelofabianov/doberman/msg"
)

const (
	lowerChars  = "abcdefghijklmnopqrstuvwxyz"
	upperChars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numberChars = "0123456789"
	symbolChars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
)

var (
	hasNumberRegex = regexp.MustCompile(`[0-9]`)
	hasUpperRegex  = regexp.MustCompile(`[A-Z]`)
	hasLowerRegex  = regexp.MustCompile(`[a-z]`)
	hasSymbolRegex = regexp.MustCompile(`[^a-zA-Z0-9]`)
)

type PasswordConfig struct {
	MinLength     int
	RequireNumber bool
	RequireUpper  bool
	RequireLower  bool
	RequireSymbol bool
}

var DefaultPasswordConfig = &PasswordConfig{
	MinLength:     10,
	RequireNumber: true,
	RequireUpper:  true,
	RequireLower:  true,
	RequireSymbol: true,
}

type PasswordValidator struct {
	config *PasswordConfig
}

func NewPasswordValidator(config *PasswordConfig) *PasswordValidator {
	if config == nil {
		config = DefaultPasswordConfig
	}
	return &PasswordValidator{config: config}
}

func (v *PasswordValidator) Generate() (Password, error) {
	var result []rune
	var allChars string

	if v.config.RequireLower {
		char, err := randomCharFromString(lowerChars)
		if err != nil {
			return "", err
		}
		result = append(result, char)
		allChars += lowerChars
	}
	if v.config.RequireUpper {
		char, err := randomCharFromString(upperChars)
		if err != nil {
			return "", err
		}
		result = append(result, char)
		allChars += upperChars
	}
	if v.config.RequireNumber {
		char, err := randomCharFromString(numberChars)
		if err != nil {
			return "", err
		}
		result = append(result, char)
		allChars += numberChars
	}
	if v.config.RequireSymbol {
		char, err := randomCharFromString(symbolChars)
		if err != nil {
			return "", err
		}
		result = append(result, char)
		allChars += symbolChars
	}

	remainingLen := v.config.MinLength - len(result)
	for i := 0; i < remainingLen; i++ {
		char, err := randomCharFromString(allChars)
		if err != nil {
			return "", err
		}
		result = append(result, char)
	}

	_, err := io.ReadFull(rand.Reader, make([]byte, len(result)))
	if err != nil {
		return "", err
	}

	for i := len(result) - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		j := jBig.Int64()
		result[i], result[j] = result[j], result[i]
	}

	return Password(string(result)), nil
}

func randomCharFromString(s string) (rune, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(s))))
	if err != nil {
		return 0, err
	}
	return rune(s[n.Int64()]), nil
}

func (v *PasswordValidator) Validate(passwordStr string) error {
	if passwordStr == "" {
		return msg.NewValidationError(nil, map[string]any{"field": "password"}, "Password cannot be empty.")
	}

	passwordRuneLen := utf8.RuneCountInString(passwordStr)
	if v.config.MinLength > 0 && passwordRuneLen < v.config.MinLength {
		message := fmt.Sprintf("Password must be at least %d characters long.", v.config.MinLength)
		return msg.NewValidationError(nil, map[string]any{"field": "password", "min_length": v.config.MinLength, "actual_length": passwordRuneLen}, message)
	}

	if v.config.RequireNumber && !hasNumberRegex.MatchString(passwordStr) {
		return msg.NewValidationError(nil, map[string]any{"field": "password", "rule_violation": "missing_numeric"}, "Password must contain at least one numeric character (0-9).")
	}

	if v.config.RequireUpper && !hasUpperRegex.MatchString(passwordStr) {
		return msg.NewValidationError(nil, map[string]any{"field": "password", "rule_violation": "missing_uppercase"}, "Password must contain at least one uppercase letter (A-Z).")
	}

	if v.config.RequireLower && !hasLowerRegex.MatchString(passwordStr) {
		return msg.NewValidationError(nil, map[string]any{"field": "password", "rule_violation": "missing_lowercase"}, "Password must contain at least one lowercase letter (a-z).")
	}

	if v.config.RequireSymbol && !hasSymbolRegex.MatchString(passwordStr) {
		return msg.NewValidationError(nil, map[string]any{"field": "password", "rule_violation": "missing_symbol"}, "Password must contain at least one symbol.")
	}

	return nil
}

func (v *PasswordValidator) NewPassword(passwordStr string) (Password, error) {
	if err := v.Validate(passwordStr); err != nil {
		return "", err
	}
	return Password(passwordStr), nil
}

var defaultValidator = NewPasswordValidator(DefaultPasswordConfig)

func NewPassword(passwordStr string) (Password, error) {
	return defaultValidator.NewPassword(passwordStr)
}

type Password string

func MustNewPassword(passwordStr string) Password {
	p, err := NewPassword(passwordStr)
	if err != nil {
		panic(err)
	}
	return p
}

func (p Password) String() string {
	return string(p)
}

func (p Password) IsEmpty() bool {
	return string(p) == ""
}

func (p Password) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

func (p *Password) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return msg.NewMessageError(err, "Password must be a valid JSON string.", msg.CodeInvalid, nil)
	}
	newP, err := NewPassword(s)
	if err != nil {
		return err
	}
	*p = newP
	return nil
}

func (p Password) MarshalText() ([]byte, error) {
	return []byte(p.String()), nil
}

func (p *Password) UnmarshalText(text []byte) error {
	s := string(text)
	newP, err := NewPassword(s)
	if err != nil {
		return err
	}
	*p = newP
	return nil
}

func (p Password) Value() (driver.Value, error) {
	if p.IsEmpty() {
		return nil, nil
	}
	return p.String(), nil
}

func (p *Password) Scan(src interface{}) error {
	if src == nil {
		*p = ""
		return nil
	}
	var passwordStr string
	switch sval := src.(type) {
	case string:
		passwordStr = sval
	case []byte:
		passwordStr = string(sval)
	default:
		message := fmt.Sprintf("Incompatible type (%T) for Password scan.", src)
		return msg.NewValidationError(nil, map[string]any{"received_type": fmt.Sprintf("%T", src)}, message)
	}
	newP, err := NewPassword(passwordStr)
	if err != nil {
		return err
	}
	*p = newP
	return nil
}
