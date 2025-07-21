package hasher

import "github.com/marcelofabianov/doberman/types"

type Hasher interface {
	Hash(p types.Password) (types.HashedPassword, error)
	Compare(p types.Password, h types.HashedPassword) (bool, error)
}
