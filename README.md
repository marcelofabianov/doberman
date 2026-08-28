# Doberman

Doberman is a Go package for secure password validation and hashing. It provides a
customizable password validator, Argon2id hashing, safe JSON serialization, and
integration with SQL databases through the `database/sql` package.

## Features

- Validate passwords against configurable rules (minimum length, required numbers, uppercase, lowercase, symbols).
- Hash and verify passwords with Argon2id, using the standard PHC encoded format.
- Distinct `Password` and `HashedPassword` types, so plaintext and hashes cannot be mixed up by accident.
- Safe JSON marshaling: a `Password` is always serialized as `"[REDACTED]"`.
- SQL database integration through the `Scan` and `Value` methods.
- Structured error handling using the `github.com/marcelofabianov/fault` package.

## Installation

To use Doberman in your Go project, run:

```bash
go get github.com/marcelofabianov/doberman
```

## Usage

### Creating a Password Validator

Create a `PasswordValidator` with the default or a custom configuration:

```go
package main

import (
    "fmt"

    "github.com/marcelofabianov/doberman"
)

func main() {
    // Default configuration: min length 10, requires number, uppercase, lowercase and symbol.
    validator := doberman.NewPasswordValidator(nil)

    // Custom configuration.
    customValidator := doberman.NewPasswordValidator(&doberman.PasswordConfig{
        MinLength:     12,
        RequireNumber: true,
        RequireUpper:  true,
        RequireLower:  true,
        RequireSymbol: false,
    })

    fmt.Println(validator.Validate("MySecureP@ss1"))
    fmt.Println(customValidator.Validate("MySecureP@ss1"))
}
```

### Validating a Password

Validate a password against the configured rules:

```go
if err := validator.Validate("MySecureP@ss1"); err != nil {
    fmt.Printf("Validation failed: %v\n", err)
} else {
    fmt.Println("Password is valid")
}
```

### Creating a Password

`NewPassword` validates the string with the default configuration and returns a
`Password`:

```go
password, err := doberman.NewPassword("MySecureP@ss1")
if err != nil {
    fmt.Printf("Invalid password: %v\n", err)
    return
}
fmt.Printf("Created password: %s\n", password.String())
```

To build a `Password` with a custom configuration, use the validator directly:

```go
password, err := customValidator.NewPassword("MySecureP@ss1")
```

For panic-on-error behavior (useful in tests and constants):

```go
password := doberman.MustNewPassword("MySecureP@ss1")
```

### Hashing and Verifying a Password

`Argo2Hasher` implements the `PasswordHasher` interface using Argon2id:

```go
type PasswordHasher interface {
    Hash(p Password) (HashedPassword, error)
    Compare(p Password, h HashedPassword) error
}
```

```go
// Default parameters: t=1, m=64MB, p=4, salt 16 bytes, key 32 bytes.
hasher := doberman.NewArgo2Hasher(nil)

password := doberman.MustNewPassword("MySecureP@ss1")

hashed, err := hasher.Hash(password)
if err != nil {
    fmt.Printf("Error hashing password: %v\n", err)
    return
}
fmt.Printf("Hashed password: %s\n", hashed.String())

// Verify a password against a stored hash.
if err := hasher.Compare(password, hashed); err != nil {
    if errors.Is(err, doberman.ErrMismatch) {
        fmt.Println("Password does not match")
        return
    }
    fmt.Printf("Error comparing password: %v\n", err)
    return
}
fmt.Println("Password matches")
```

The cost parameters can be customized:

```go
hasher := doberman.NewArgo2Hasher(&doberman.Config{
    Time:        2,
    Memory:      128 * 1024,
    Parallelism: 2,
    SaltLength:  16,
    KeyLength:   32,
})
```

Hashes are stored in the standard PHC string format:

```
$argon2id$v=19$m=65536,t=1,p=4$<base64-salt>$<base64-hash>
```

Because the parameters are embedded in the hash itself, `Compare` reads them from
the stored value rather than from the current configuration. This means you can
raise the cost parameters over time without invalidating existing hashes.

### Database Integration

Both `Password` and `HashedPassword` implement `driver.Valuer` and `sql.Scanner`,
so they can be passed to and read from the database directly. An empty value is
stored as `NULL`.

In practice you store the `HashedPassword`, never the plaintext:

```go
import (
    "database/sql"
    "fmt"

    "github.com/marcelofabianov/doberman"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    db, err := sql.Open("sqlite3", ":memory:")
    if err != nil {
        fmt.Printf("Error opening database: %v\n", err)
        return
    }
    defer db.Close()

    if _, err := db.Exec("CREATE TABLE users (id INTEGER PRIMARY KEY, password TEXT)"); err != nil {
        fmt.Printf("Error creating table: %v\n", err)
        return
    }

    hasher := doberman.NewArgo2Hasher(nil)

    password, err := doberman.NewPassword("DatabaseP@ss1")
    if err != nil {
        fmt.Printf("Invalid password: %v\n", err)
        return
    }

    hashed, err := hasher.Hash(password)
    if err != nil {
        fmt.Printf("Error hashing password: %v\n", err)
        return
    }

    if _, err := db.Exec("INSERT INTO users (password) VALUES (?)", hashed); err != nil {
        fmt.Printf("Error inserting: %v\n", err)
        return
    }

    var stored doberman.HashedPassword
    if err := db.QueryRow("SELECT password FROM users WHERE id = 1").Scan(&stored); err != nil {
        fmt.Printf("Error querying: %v\n", err)
        return
    }

    if err := hasher.Compare(password, stored); err != nil {
        fmt.Println("Password does not match")
        return
    }
    fmt.Println("Password matches")
}
```

Note that `Password.Scan` also validates the value it reads, so a value that no
longer satisfies the current rules will fail on read.

## JSON Serialization

`Password` never exposes its value through JSON — it is always marshaled as
`"[REDACTED]"`, which keeps plaintext passwords out of logs and API responses.
Unmarshaling validates the incoming value:

```go
type LoginRequest struct {
    Email    string             `json:"email"`
    Password doberman.Password  `json:"password"`
}

// Marshaling a LoginRequest produces: {"email":"...","password":"[REDACTED]"}
```

`HashedPassword` is marshaled and unmarshaled as its literal string value.

## Error Handling

Doberman returns errors from the `fault` package, which carry a message, a code,
and contextual data. Use `fault.AsFault` to inspect them:

```go
if _, err := doberman.NewPassword("invalid"); err != nil {
    if fErr, ok := fault.AsFault(err); ok {
        fmt.Printf("Error: %s, Code: %s, Context: %v\n", fErr.Message, fErr.Code, fErr.Context)
    }
}
```

Validation failures use the `fault.Invalid` code, a password that does not match
its hash returns `ErrMismatch` with the `fault.Unauthorized` code, and malformed
hashes or internal failures use `fault.Internal`.

## Testing

Run the tests to verify functionality:

```bash
go test -v ./...
```

## Contributing

Contributions are welcome! Please submit issues or pull requests to the [GitHub repository](https://github.com/marcelofabianov/doberman).

## License

This project is licensed under the MIT License.
