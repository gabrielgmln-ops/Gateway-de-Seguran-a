// Caminho: cmd/gateway/main.go
//
// Ponto de entrada do Gateway de Segurança.
//
// Comparação com Python: "package main" com uma "func main()" é o equivalente a
// um script com "if __name__ == '__main__':". A convenção em Go é deixar cada
// executável em cmd/<nome>/ e o código reutilizável em internal/.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gateway-seguranca/internal/config"
	"gateway-seguranca/internal/server"
)

func main() {
	// slog é o logger estruturado da biblioteca padrão. O handler JSON gera uma
	// linha JSON por evento, como o python-json-logger.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("configuração inválida", "error", err.Error())
		os.Exit(1) // como sys.exit(1)
	}

	srv := &http.Server{
		Addr:    cfg.Addr,
		Handler: server.NewRouter(cfg, logger),
		// Timeouts do servidor: sem eles, um cliente que envia os bytes muito devagar
		// (ataque Slowloris) prende conexões indefinidamente (OWASP API4).
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MiB ("<<" é deslocamento de bits, igual ao Python)
	}

	// Contexto cancelado quando chega SIGINT (Ctrl+C) ou SIGTERM (docker stop).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// "defer" agenda a chamada para quando a função terminar, como um "finally".
	defer stop()

	// "go func() { ... }()" roda a função em uma goroutine, uma thread leve gerenciada
	// pelo Go. É parecido com threading.Thread(target=...).start(), porém muito mais barato.
	go func() {
		logger.Info("gateway iniciado", "addr", cfg.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("falha no servidor", "error", err.Error())
			os.Exit(1)
		}
	}()

	<-ctx.Done() // bloqueia até chegar o sinal ("<-" lê de um canal, como queue.get())
	logger.Info("desligando o gateway, aguardando requisições em andamento")

	// Graceful shutdown: para de aceitar conexões novas e espera até 10s pelas atuais,
	// para que nenhuma transação Pix seja cortada no meio.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("erro no desligamento", "error", err.Error())
		os.Exit(1)
	}
	logger.Info("gateway encerrado")
}
