# doberman 🐕‍🦺

[![Go Report Card](https://goreportcard.com/badge/github.com/marcelofabianov/doberman)](https://goreportcard.com/report/github.com/marcelofabianov/doberman)
[![Go Reference](https://pkg.go.dev/badge/github.com/marcelofabianov/doberman.svg)](https://pkg.go.dev/github.com/marcelofabianov/doberman)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`doberman` é uma biblioteca Go completa e segura, projetada para gerenciar todo o ciclo de vida de senhas com elegância e precisão. Ele atua como um "cão de guarda" para a segurança da sua aplicação, garantindo que as senhas sejam validadas, geradas e armazenadas da forma mais segura possível.

## ✨ Principais Funcionalidades

* **Hashing Seguro:** Utiliza **Argon2id**, o algoritmo recomendado pela OWASP para hashing de senhas.
* **Políticas de Senha Configuráveis:** Defina com facilidade as regras de complexidade (comprimento, caracteres obrigatórios, etc.) através do `PasswordValidator`.
* **Geração de Senhas Seguras:** Crie senhas aleatórias e fortes que aderem automaticamente às políticas de validação que você definir.
* **Segurança de Tipos (Type-Safety):** Usa tipos ricos como `types.Password` e `types.HashedPassword` para prevenir erros comuns de programação, como usar um hash como se fosse uma senha em texto plano.
* **Erros Estruturados:** Integrado com o pacote [fault](https://github.com/marcelofabianov/fault), retorna erros ricos em contexto, facilitando a depuração e o tratamento de falhas na API.
* **Design Desacoplado:** Baseado em interfaces (`PasswordHasher`) para facilitar os testes e futuras extensões.

## 🚀 Instalação

```bash
go get [github.com/marcelofabianov/doberman](https://github.com/marcelofabianov/doberman)
```

## 💡 Uso e Conceitos

O `doberman` é dividido em duas responsabilidades principais: validação/geração de senhas (`PasswordValidator`) e hashing/comparação (`PasswordHasher`).

### 1. Validando Senhas

Você pode usar o validador com as regras padrão ou criar o seu próprio.

```go
import "[github.com/marcelofabianov/doberman/types](https://github.com/marcelofabianov/doberman/types)"

// Usando a política padrão (10+ chars, maiúscula, minúscula, número, símbolo)
validatorPadrao := types.NewPasswordValidator(nil)
_, err := validatorPadrao.NewPassword("SenhaFraca1")
if err != nil {
    // err será um *fault.Error com Code 'invalid_input'
    fmt.Println(err)
}

// Usando uma política customizada
configSimples := &types.PasswordConfig{
    MinLength:     8,
    RequireNumber: true,
}
validatorSimples := types.NewPasswordValidator(configSimples)
senhaValida, err := validatorSimples.NewPassword("senha123")
if err == nil {
    fmt.Println("Senha simples, porém válida para esta política!")
}
```

### 2. Gerando Senhas Seguras

O mesmo `PasswordValidator` pode gerar senhas que cumprem suas próprias regras.

```go
// Gera uma senha que atende à política do 'validatorSimples'
senhaGerada, err := validatorSimples.Generate()
if err != nil {
    // Tratar erro raro de geração
}

fmt.Printf("Senha gerada: %s\n", senhaGerada)
```

### 3. Hasheando e Comparando Senhas

O `PasswordHasher` cuida do armazenamento seguro.

```go
import (
    "[github.com/marcelofabianov/doberman/hasher](https://github.com/marcelofabianov/doberman/hasher)"
    "[github.com/marcelofabianov/doberman/types](https://github.com/marcelofabianov/doberman/types)"
)

// 1. Crie uma instância do hasher (usando a implementação Argon2id padrão)
argonHasher := hasher.NewArgo2Hasher(nil)

// 2. Crie uma instância de senha válida
senhaPlana, _ := types.NewPassword("StrongPassword123!")

// 3. Gere o hash
senhaHasheada, err := argonHasher.Hash(senhaPlana)
if err != nil {
    // Tratar erro de hash
}

// 4. Armazene 'senhaHasheada' no seu banco de dados
fmt.Printf("Hash seguro para armazenar: %s\n", senhaHasheada)

// 5. Em um fluxo de login, compare a tentativa com o hash armazenado
match, err := argonHasher.Compare(senhaPlana, senhaHasheada)
if err == nil && match {
    fmt.Println("Login bem-sucedido!")
}
```

### Tratando Erros do Doberman

O `doberman` retorna erros do tipo `*fault.Error`, o que permite um tratamento de erro robusto. Um caso de uso comum é verificar se a senha não corresponde.

```go
import "errors"

// ... fluxo de login ...
_, err := argonHasher.Compare(tentativaDeSenha, senhaHasheada)
if err != nil {
    // errors.Is funciona perfeitamente para checar o erro de mismatch
    if errors.Is(err, hasher.ErrMismatch) {
        fmt.Println("Credenciais inválidas.")
        // Retornar um erro HTTP 401 Unauthorized
    } else {
        // Tratar outros erros (ex: hash corrompido, erro interno)
        fmt.Println("Ocorreu um erro interno:", err)
    }
}
```

## 🤝 Contribuições

Contribuições são bem-vindas! Sinta-se à vontade para abrir uma *issue* para discutir novas funcionalidades ou reportar bugs.

## 📄 Licença

Este projeto é distribuído sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.
