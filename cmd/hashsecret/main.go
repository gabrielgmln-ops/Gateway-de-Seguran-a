// Caminho: cmd/hashsecret/main.go
//
// Utilitário de linha de comando: lê um client_secret da entrada padrão e
// imprime o hash SHA-256 que vai no campo "secret_sha256" de OAUTH_CLIENTS.
// O segredo é lido do stdin (e não de um argumento) para não ficar gravado no
// histórico do shell nem aparecer na listagem de processos (ps).
//
// Uso:
//
//	printf '%s' "$SEGREDO" | go run ./cmd/hashsecret
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"gateway-seguranca/internal/auth"
)

func main() {
	reader := bufio.NewReader(os.Stdin) // como sys.stdin no Python
	line, err := reader.ReadString('\n')
	// io.EOF sem conteúdo significa que nada foi digitado.
	secret := strings.TrimRight(line, "\r\n")
	if secret == "" {
		fmt.Fprintln(os.Stderr, "erro: informe o segredo pela entrada padrão", err)
		os.Exit(1)
	}
	if len(secret) < 32 {
		fmt.Fprintln(os.Stderr, "erro: use um segredo com pelo menos 32 caracteres (ex.: openssl rand -hex 32)")
		os.Exit(1)
	}
	fmt.Println(auth.HashSecret(secret))
}
