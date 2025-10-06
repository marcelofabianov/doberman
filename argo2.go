package doberman

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/marcelofabianov/fault"
	"golang.org/x/crypto/argon2"
)

var ErrMismatch = fault.New("password does not match hash", fault.WithCode(fault.Unauthorized))

type Config struct {
	Time        uint32
	Memory      uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var DefaultConfig = &Config{
	Time:        1,
	Memory:      64 * 1024,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32,
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

func (h *Argo2Hasher) Hash(p Password) (HashedPassword, *fault.Error) {
	salt := make([]byte, h.config.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fault.Wrap(err,
			"failed to generate random salt for hashing",
			fault.WithCode(fault.Internal),
		)
	}

	hash := argon2.IDKey(
		[]byte(p.String()),
		salt,
		h.config.Time,
		h.config.Memory,
		h.config.Parallelism,
		h.config.KeyLength,
	)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		h.config.Memory,
		h.config.Time,
		h.config.Parallelism,
		b64Salt,
		b64Hash,
	)

	return NewHashedPassword(encodedHash), nil
}

type decodedHash struct {
	params Config
	salt   []byte
	hash   []byte
}

func parseEncodedHash(encodedHash HashedPassword) (*decodedHash, *fault.Error) {
	parts := strings.Split(encodedHash.String(), "$")
	if len(parts) != 6 {
		return nil, fault.New("invalid hash format",
			fault.WithCode(fault.Internal),
			fault.WithContext("reason", "expecting 6 parts"),
			fault.WithContext("parts_found", len(parts)),
		)
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return nil, fault.Wrap(err,
			"could not parse argon2 version from hash",
			fault.WithCode(fault.Internal),
		)
	}
	if version != argon2.Version {
		return nil, fault.New("incompatible argon2 version",
			fault.WithCode(fault.Internal),
			fault.WithContext("expected_version", argon2.Version),
			fault.WithContext("actual_version", version),
		)
	}

	var params Config
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Time, &params.Parallelism)
	if err != nil {
		return nil, fault.Wrap(err,
			"could not parse argon2 params from hash",
			fault.WithCode(fault.Internal),
		)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, fault.Wrap(err,
			"could not decode salt from hash",
			fault.WithCode(fault.Internal),
		)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, fault.Wrap(err,
			"could not decode hash part from encoded string",
			fault.WithCode(fault.Internal),
		)
	}

	return &decodedHash{
		params: params,
		salt:   salt,
		hash:   hash,
	}, nil
}

func (h *Argo2Hasher) Compare(p Password, encodedHash HashedPassword) error {
	decoded, err := parseEncodedHash(encodedHash)
	if err != nil {
		return err
	}

	comparisonHash := argon2.IDKey(
		[]byte(p.String()),
		decoded.salt,
		decoded.params.Time,
		decoded.params.Memory,
		decoded.params.Parallelism,
		uint32(len(decoded.hash)),
	)

	if subtle.ConstantTimeCompare(decoded.hash, comparisonHash) == 1 {
		return nil
	}

	return ErrMismatch
}
