package doberman

import (
	"github.com/marcelofabianov/fault"
)

type PasswordHasher interface {
	Hash(p Password) (HashedPassword, *fault.Error)
	Compare(p Password, h HashedPassword) error
}
