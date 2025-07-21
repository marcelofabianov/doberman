package hasher

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrMismatch            = errors.New("hasher: password does not match hash")
	ErrInvalidHashFormat   = errors.New("hasher: invalid hash format")
	ErrIncompatibleVersion = errors.New("hasher: incompatible argon2 version")
)

type Config struct {
	time        uint32
	memory      uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

var DefaultConfig = &Config{
	time:        1,
	memory:      64 * 1024,
	parallelism: 4,
	saltLength:  16,
	keyLength:   32,
}

type Argo2Hasher struct {
	config *Config
}

func NewArgo2Hasher(config *Config) *Argo2Hasher {
	if config == nil {
		config = DefaultConfig
	}
	return &Argo2Hasher{config: config}
}

func (h *Argo2Hasher) Hash(data string) (string, error) {
	salt := make([]byte, h.config.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(data),
		salt,
		h.config.time,
		h.config.memory,
		h.config.parallelism,
		h.config.keyLength,
	)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		h.config.memory,
		h.config.time,
		h.config.parallelism,
		b64Salt,
		b64Hash,
	)

	return encodedHash, nil
}

func (h *Argo2Hasher) Compare(data, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, ErrInvalidHashFormat
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return false, ErrInvalidHashFormat
	}
	if version != argon2.Version {
		return false, ErrIncompatibleVersion
	}

	var p Config
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.parallelism)
	if err != nil {
		return false, ErrInvalidHashFormat
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrInvalidHashFormat
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, ErrInvalidHashFormat
	}

	comparisonHash := argon2.IDKey(
		[]byte(data),
		salt,
		p.time,
		p.memory,
		p.parallelism,
		uint32(len(hash)),
	)

	if subtle.ConstantTimeCompare(hash, comparisonHash) == 1 {
		return true, nil
	}

	return false, ErrMismatch
}
