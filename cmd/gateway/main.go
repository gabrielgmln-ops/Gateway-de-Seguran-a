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
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"gateway-seguranca/internal/auth"
	"gateway-seguranca/internal/clientip"
	"gateway-seguranca/internal/config"
	"gateway-seguranca/internal/ipblock"
	"gateway-seguranca/internal/ratelimit"
	"gateway-seguranca/internal/seclog"
	"gateway-seguranca/internal/server"
)

func main() {
	// slog é o logger estruturado da biblioteca padrão. O handler JSON gera uma
	// linha JSON por evento, como o python-json-logger.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// "gateway healthcheck": modo usado pelo healthcheck do Docker. A imagem
	// distroless não tem curl nem shell, então o próprio binário faz a checagem.
	// os.Args é o sys.argv do Python.
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}

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

	// --- Bloqueio de IP e IP real do cliente ---
	blocker, err := ipblock.New(rdb, cfg.IPBlockMaxFailures, cfg.IPBlockWindow, cfg.IPBlockDuration)
	if err != nil {
		return err
	}
	ipResolver, err := clientip.New(cfg.TrustedProxies)
	if err != nil {
		return err
	}

	// --- Logs de segurança: sempre no stdout e, se configurado, também no PostgreSQL ---
	readyChecks := map[string]func(context.Context) error{
		"redis": func(ctx context.Context) error { return rdb.Ping(ctx).Err() },
	}
	sinks := []seclog.Sink{seclog.NewSlogSink(logger)}
	var pgSink *seclog.PostgresSink
	if cfg.DatabaseURL != "" {
		err := waitFor("postgres", logger, func(ctx context.Context) error {
			var e error
			pgSink, e = seclog.NewPostgresSink(ctx, cfg.DatabaseURL, cfg.SecLogBuffer, logger)
			return e
		})
		if err != nil {
			return err
		}
		sinks = append(sinks, pgSink)
		readyChecks["postgres"] = pgSink.Ping
	} else {
		logger.Warn("DATABASE_URL vazia: eventos de segurança apenas no stdout")
	}

	// O Monitor recebe o blocker: cada falha de segurança conta para o bloqueio do IP.
	monitor := seclog.NewMonitor(logger, blocker, sinks...)

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
			Blocker:       blocker,
			ClientIP:      ipResolver.ClientIP, // um método pode ser passado como valor, como no Python
			ReadyChecks:   readyChecks,
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
	// Só depois que o servidor parou é seguro fechar a fila de eventos.
	if pgSink != nil {
		pgSink.Close()
		if n := pgSink.Dropped(); n > 0 {
			logger.Warn("eventos de segurança descartados por fila cheia", "total", n)
		}
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

// healthcheck consulta o /healthz local e devolve o código de saída (0 = saudável).
func healthcheck() int {
	addr := os.Getenv("GATEWAY_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if strings.HasPrefix(addr, ":") { // ":8080" -> "127.0.0.1:8080"
		addr = "127.0.0.1" + addr
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + addr + "/healthz")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
