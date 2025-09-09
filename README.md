# Doberman

Doberman is a Go package for secure password generation, validation, and handling. It provides a customizable password validator, supports JSON serialization/deserialization, and integrates with SQL databases using the `database/sql` package.

## Features

- Generate random passwords with customizable requirements (length, character types).
- Validate passwords against configurable rules (minimum length, required numbers, uppercase, lowercase, symbols).
- Securely handle passwords with JSON marshaling/unmarshaling.
- Support for SQL database integration with `Scan` and `Value` methods.
- Error handling using the `github.com/marcelofabianov/fault` package.

## Installation

To use Doberman in your Go project, run:

```bash
go get github.com/marcelofabianov/doberman
```

Ensure you have the `fault` package installed:

```bash
go get github.com/marcelofabianov/fault
```

## Usage

### Creating a Password Validator

Create a `PasswordValidator` with default or custom configuration:

```go
package main

import (
    "fmt"
    "github.com/marcelofabianov/doberman"
)

func main() {
    // Use default configuration (min length: 10, requires number, uppercase, lowercase, symbol)
    validator := doberman.NewPasswordValidator(nil)

    // Custom configuration
    customConfig := &doberman.PasswordConfig{
        MinLength:     12,
        RequireNumber: true,
        RequireUpper:  true,
        RequireLower:  true,
        RequireSymbol: false,
    }
    customValidator := doberman.NewPasswordValidator(customConfig)
}
```

### Generating a Password

Generate a random password that meets the validator's requirements:

```go
password, err := validator.Generate()
if err != nil {
    fmt.Printf("Error generating password: %v\n", err)
    return
}
fmt.Printf("Generated password: %s\n", password.String())
```

### Validating a Password

Validate a password against the configured rules:

```go
err := validator.Validate("MySecureP@ss1")
if err != nil {
    fmt.Printf("Validation failed: %v\n", err)
} else {
    fmt.Println("Password is valid")
}
```

### Creating a Password

Create a `Password` type with validation:

```go
password, err := doberman.NewPassword("MySecureP@ss1")
if err != nil {
    fmt.Printf("Invalid password: %v\n", err)
    return
}
fmt.Printf("Created password: %s\n", password.String())
```

For panic-on-error behavior:

```go
password := doberman.MustNewPassword("MySecureP@ss1")
fmt.Printf("Created password: %s\n", password.String())
```

### Database Integration

Use the `Password` type with SQL databases:

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

    // Create table
    _, err = db.Exec("CREATE TABLE users (id INTEGER PRIMARY KEY, password TEXT)")
    if err != nil {
        fmt.Printf("Error creating table: %v\n", err)
        return
    }

    // Insert password
    password, _ := doberman.NewPassword("DatabaseP@ss1")
    _, err = db.Exec("INSERT INTO users (password) VALUES (?)", password)
    if err != nil {
        fmt.Printf("Error inserting: %v\n", err)
        return
    }

    // Query password
    var scannedPassword doberman.Password
    err = db.QueryRow("SELECT password FROM users WHERE id = 1").Scan(&scannedPassword)
    if err != nil {
        fmt.Printf("Error querying: %v\n", err)
        return
    }
    fmt.Printf("Scanned password: %s\n", scannedPassword.String())
}
```

## Error Handling

Doberman uses the `fault` package for structured error handling. Errors include a message, code, context, and wrapped errors:

```go
password, err := doberman.NewPassword("invalid")
if err != nil {
    fmt.Printf("Error: %s, Code: %s, Context: %v\n", err.Message, err.Code, err.Context)
}
```

## Testing

Run the tests to verify functionality:

```bash
go test -v ./...
```

## Contributing

Contributions are welcome! Please submit issues or pull requests to the [GitHub repository](https://github.com/marcelofabianov/doberman).

## License

This project is licensed under the MIT License.
