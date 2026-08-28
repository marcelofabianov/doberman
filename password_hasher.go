package doberman

type PasswordHasher interface {
	Hash(p Password) (HashedPassword, error)
	Compare(p Password, h HashedPassword) error
}
