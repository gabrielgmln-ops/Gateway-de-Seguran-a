// Caminho: internal/seclog/postgres.go
//
// Sink que grava os eventos de segurança no PostgreSQL de forma ASSÍNCRONA.
//
// Por que assíncrono? Se cada requisição esperasse um INSERT, um banco lento
// deixaria o gateway inteiro lento, e um atacante poderia gerar milhares de
// eventos para derrubá-lo. Aqui os eventos entram numa fila em memória (um
// "channel") e uma goroutine os grava em lotes. Se a fila encher, o evento é
// descartado e contado (ele continua no log de stdout), em vez de travar.
package seclog

import (
	"context"
	_ "embed" // import só pelo efeito colateral: habilita a diretiva //go:embed
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A diretiva abaixo embute o conteúdo do arquivo SQL na variável DURANTE a
// compilação. O binário fica autossuficiente, sem precisar do .sql no disco.
// (Em Python, o mais próximo seria importlib.resources.)
//
//go:embed migrations/001_security_events.sql
var migrationSQL string

const (
	batchSize     = 100
	flushInterval = time.Second
)

// PostgresSink implementa Sink.
type PostgresSink struct {
	pool    *pgxpool.Pool
	queue   chan Event     // fila com capacidade limitada
	dropped atomic.Uint64  // contador seguro para várias goroutines ao mesmo tempo
	wg      sync.WaitGroup // espera a goroutine de gravação terminar (como thread.join())
	logger  *slog.Logger
}

// NewPostgresSink conecta, aplica a migração e inicia a goroutine de gravação.
func NewPostgresSink(ctx context.Context, databaseURL string, bufferSize int, logger *slog.Logger) (*PostgresSink, error) {
	poolCfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		// Não inclua o erro original: ele poderia conter a URL com a senha.
		return nil, fmt.Errorf("DATABASE_URL inválida")
	}
	poolCfg.MaxConns = 5 // o gateway só faz INSERTs; poucas conexões bastam

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("conectar ao postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping no postgres: %w", err)
	}
	if _, err := pool.Exec(ctx, migrationSQL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("aplicar migração: %w", err)
	}

	s := &PostgresSink{
		pool:   pool,
		queue:  make(chan Event, bufferSize),
		logger: logger,
	}
	s.wg.Add(1)
	go s.run()
	return s, nil
}

// Write coloca o evento na fila SEM BLOQUEAR.
func (s *PostgresSink) Write(e Event) {
	// "select" com "default": se o envio não for possível agora (fila cheia),
	// cai no default em vez de esperar. É como queue.put_nowait() do Python.
	select {
	case s.queue <- e:
	default:
		s.dropped.Add(1)
	}
}

// Dropped devolve quantos eventos foram descartados por fila cheia.
func (s *PostgresSink) Dropped() uint64 { return s.dropped.Load() }

// Ping verifica a conexão (usado pelo /readyz).
func (s *PostgresSink) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Close fecha a fila, grava o que restou e encerra as conexões.
// Só deve ser chamado depois que o servidor HTTP parou de receber requisições.
func (s *PostgresSink) Close() {
	close(s.queue) // sinaliza para a goroutine que não virão mais eventos
	s.wg.Wait()
	s.pool.Close()
}

// run é a goroutine de gravação: acumula até batchSize eventos ou espera
// flushInterval, o que acontecer primeiro.
func (s *PostgresSink) run() {
	defer s.wg.Done()
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	batch := make([]Event, 0, batchSize)
	for {
		select {
		case e, ok := <-s.queue:
			if !ok { // fila fechada pelo Close(): grava o restante e sai
				s.flush(batch)
				return
			}
			batch = append(batch, e)
			if len(batch) >= batchSize {
				s.flush(batch)
				batch = batch[:0] // esvazia mantendo a memória alocada
			}
		case <-ticker.C:
			if len(batch) > 0 {
				s.flush(batch)
				batch = batch[:0]
			}
		}
	}
}

// flush grava um lote com um único round-trip ao banco (pgx.Batch).
// Os valores vão como PARÂMETROS ($1, $2...), nunca concatenados no SQL:
// isso impede SQL injection mesmo com campos controlados pelo atacante (como o path).
func (s *PostgresSink) flush(events []Event) {
	if len(events) == 0 {
		return
	}
	const q = `INSERT INTO security_events
		(occurred_at, event_type, severity, request_id, client_ip, client_id, method, path, status, detail)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	b := &pgx.Batch{}
	for _, e := range events {
		b.Queue(q, e.Time, string(e.Type), e.Severity, e.RequestID, e.ClientIP, e.ClientID,
			e.Method, e.Path, e.Status, e.Detail)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.pool.SendBatch(ctx, b).Close(); err != nil {
		s.logger.Error("falha ao gravar eventos de segurança no postgres",
			"error", err.Error(), "eventos_perdidos", len(events))
	}
}
