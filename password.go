package doberman

import (
	"crypto/rand"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/marcelofabianov/fault"
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

func (v *PasswordValidator) Generate() (Password, *fault.Error) {
	var result []rune
	var allChars string

	// Default to lowercase letters to prevent empty allChars
	allChars = lowerChars

	if v.config.RequireLower {
		char, err := randomCharFromString(lowerChars)
		if err != nil {
			return "", fault.Wrap(err, "failed to generate random character for lowercase", fault.WithCode(fault.Internal))
		}
		result = append(result, char)
		if !strings.Contains(allChars, lowerChars) {
			allChars += lowerChars
		}
	}
	if v.config.RequireUpper {
		char, err := randomCharFromString(upperChars)
		if err != nil {
			return "", fault.Wrap(err, "failed to generate random character for uppercase", fault.WithCode(fault.Internal))
		}
		result = append(result, char)
		if !strings.Contains(allChars, upperChars) {
			allChars += upperChars
		}
	}
	if v.config.RequireNumber {
		char, err := randomCharFromString(numberChars)
		if err != nil {
			return "", fault.Wrap(err, "failed to generate random character for number", fault.WithCode(fault.Internal))
		}
		result = append(result, char)
		if !strings.Contains(allChars, numberChars) {
			allChars += numberChars
		}
	}
	if v.config.RequireSymbol {
		char, err := randomCharFromString(symbolChars)
		if err != nil {
			return "", fault.Wrap(err, "failed to generate random character for symbol", fault.WithCode(fault.Internal))
		}
		result = append(result, char)
		if !strings.Contains(allChars, symbolChars) {
			allChars += symbolChars
		}
	}

	remainingLen := v.config.MinLength - len(result)
	for i := 0; i < remainingLen; i++ {
		char, err := randomCharFromString(allChars)
		if err != nil {
			return "", fault.Wrap(err, "failed to generate random character for remainder", fault.WithCode(fault.Internal))
		}
		result = append(result, char)
	}

	for i := len(result) - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", fault.Wrap(err, "failed to shuffle password", fault.WithCode(fault.Internal))
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

func (v *PasswordValidator) Validate(passwordStr string) *fault.Error {
	if passwordStr == "" {
		return fault.New("password cannot be empty",
			fault.WithCode(fault.Invalid),
			fault.WithContext("field", "password"),
		)
	}

	passwordRuneLen := utf8.RuneCountInString(passwordStr)
	if v.config.MinLength > 0 && passwordRuneLen < v.config.MinLength {
		message := fmt.Sprintf("password must be at least %d characters long", v.config.MinLength)
		return fault.New(message,
			fault.WithCode(fault.Invalid),
			fault.WithContext("min_length", v.config.MinLength),
		)
	}

	if v.config.RequireNumber && !hasNumberRegex.MatchString(passwordStr) {
		return fault.New("password must contain at least one numeric character (0-9)",
			fault.WithCode(fault.Invalid),
		)
	}

	if v.config.RequireUpper && !hasUpperRegex.MatchString(passwordStr) {
		return fault.New("password must contain at least one uppercase letter (A-Z)",
			fault.WithCode(fault.Invalid),
		)
	}

	if v.config.RequireLower && !hasLowerRegex.MatchString(passwordStr) {
		return fault.New("password must contain at least one lowercase letter (a-z)",
			fault.WithCode(fault.Invalid),
		)
	}

	if v.config.RequireSymbol && !hasSymbolRegex.MatchString(passwordStr) {
		return fault.New("password must contain at least one symbol",
			fault.WithCode(fault.Invalid),
		)
	}

	return nil
}

func (v *PasswordValidator) NewPassword(passwordStr string) (Password, *fault.Error) {
	if err := v.Validate(passwordStr); err != nil {
		return "", err
	}
	return Password(passwordStr), nil
}

var defaultValidator = NewPasswordValidator(DefaultPasswordConfig)

func NewPassword(passwordStr string) (Password, *fault.Error) {
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
		return fault.New("password must be a valid JSON string",
			fault.WithCode(fault.Invalid),
			fault.WithWrappedErr(err),
		)
	}
	newP, faultErr := NewPassword(s)
	if faultErr != nil {
		return faultErr
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
		return fault.New(fmt.Sprintf("incompatible type (%T) for password scan", src),
			fault.WithCode(fault.Internal),
		)
	}
	newP, err := NewPassword(passwordStr)
	if err != nil {
		return err
	}
	*p = newP
	return nil
}
