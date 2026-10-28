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
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"gateway-seguranca/internal/auth"
	"gateway-seguranca/internal/config"
	"gateway-seguranca/internal/ratelimit"
	"gateway-seguranca/internal/seclog"
	"gateway-seguranca/internal/server"
)

func main() {
	// slog é o logger estruturado da biblioteca padrão. O handler JSON gera uma
	// linha JSON por evento, como o python-json-logger.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// run() concentra a lógica e devolve um erro; main() só decide o código de saída.
	// Assim os "defer" de run() sempre executam (os.Exit pularia todos eles).
	if err := run(logger); err != nil {
		logger.Error("gateway encerrado com erro", "error", err.Error())
		os.Exit(1) // como sys.exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	tokens, err := auth.NewTokenService(cfg.JWTSecret, cfg.JWTIssuer, cfg.JWTAudience, cfg.JWTTTL)
	if err != nil {
		return err
	}
	clients, err := auth.ParseClients(cfg.OAuthClientsJSON)
	if err != nil {
		return err
	}

	// --- Redis ---
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword, // senha vem do ambiente, nunca do código
		DB:       cfg.RedisDB,
		// Timeouts curtos: o Redis está na mesma rede, e esperar muito por ele
		// só deixaria as requisições presas.
		DialTimeout:  2 * time.Second,
		ReadTimeout:  500 * time.Millisecond,
		WriteTimeout: 500 * time.Millisecond,
		PoolSize:     50,
	})
	defer rdb.Close()
	if err := waitFor("redis", logger, func(ctx context.Context) error { return rdb.Ping(ctx).Err() }); err != nil {
		return err
	}

	ipLimiter, err := ratelimit.NewRedisLimiter(rdb, "rl:global", cfg.RateIP.Capacity, cfg.RateIP.Refill)
	if err != nil {
		return err
	}
	oauthLimiter, err := ratelimit.NewRedisLimiter(rdb, "rl:oauth", cfg.RateOAuth.Capacity, cfg.RateOAuth.Refill)
	if err != nil {
		return err
	}
	clientLimiter, err := ratelimit.NewRedisLimiter(rdb, "rl:svc", cfg.RateClient.Capacity, cfg.RateClient.Refill)
	if err != nil {
		return err
	}

	// Por enquanto, eventos de segurança vão só para o stdout e não há bloqueio de IP.
	monitor := seclog.NewMonitor(logger, nil, seclog.NewSlogSink(logger))

	srv := &http.Server{
		Addr: cfg.Addr,
		Handler: server.NewRouter(server.Deps{
			Config:   cfg,
			Logger:   logger,
			Tokens:   tokens,
			Clients:  clients,
			Reporter: monitor,

			IPLimiter:     ipLimiter,
			OAuthLimiter:  oauthLimiter,
			ClientLimiter: clientLimiter,
			ReadyChecks: map[string]func(context.Context) error{
				"redis": func(ctx context.Context) error { return rdb.Ping(ctx).Err() },
			},
		}),
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

	// Canal para receber um erro da goroutine do servidor.
	// "make(chan error, 1)" cria um canal com buffer de 1, parecido com queue.Queue(maxsize=1).
	serverErr := make(chan error, 1)

	// "go func() { ... }()" roda a função em uma goroutine, uma thread leve gerenciada
	// pelo Go. É parecido com threading.Thread(target=...).start(), porém muito mais barato.
	go func() {
		logger.Info("gateway iniciado", "addr", cfg.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err // "<-" envia para o canal, como queue.put(err)
		}
	}()

	// "select" espera o primeiro de vários canais ficar pronto.
	select {
	case err := <-serverErr:
		return err
	case <-ctx.Done():
	}
	logger.Info("desligando o gateway, aguardando requisições em andamento")

	// Graceful shutdown: para de aceitar conexões novas e espera até 10s pelas atuais,
	// para que nenhuma transação Pix seja cortada no meio.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	logger.Info("gateway encerrado")
	return nil
}

// waitFor tenta a verificação algumas vezes antes de desistir. Na subida do
// Docker Compose, o Redis e o PostgreSQL podem levar alguns segundos para aceitar conexões.
func waitFor(name string, logger *slog.Logger, check func(context.Context) error) error {
	const attempts = 10
	var err error
	for i := 1; i <= attempts; i++ { // o "for" clássico de três partes, como em C
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err = check(ctx)
		cancel()
		if err == nil {
			logger.Info("dependência disponível", "dependency", name)
			return nil
		}
		logger.Warn("aguardando dependência", "dependency", name, "tentativa", i, "error", err.Error())
		time.Sleep(time.Second)
	}
	return fmt.Errorf("%s indisponível após %d tentativas: %w", name, attempts, err)
}
