// Caminho: internal/seclog/seclog_test.go
package seclog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"gateway-seguranca/internal/httpx"
)

// memorySink guarda os eventos em memória.
type memorySink struct{ events []Event }

func (m *memorySink) Write(e Event) { m.events = append(m.events, e) }

// fakeRecorder simula o ipblock.Blocker.
type fakeRecorder struct {
	calls   []string
	blockAt int
	err     error
}

func (f *fakeRecorder) RecordFailure(_ context.Context, ip string) (bool, error) {
	f.calls = append(f.calls, ip)
	return len(f.calls) == f.blockAt, f.err
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// requestWithContext cria uma requisição com o contexto já preenchido,
// como os middlewares fariam numa requisição real.
func requestWithContext() *http.Request {
	r := httptest.NewRequest("POST", "/oauth/token", nil)
	ctx := httpx.WithRequestID(r.Context(), "req-1")
	ctx = httpx.WithClientIP(ctx, "203.0.113.7")
	ctx = httpx.WithClientID(ctx, "app-pix")
	return r.WithContext(ctx)
}

func TestMonitorBuildsEventAndFeedsBlocker(t *testing.T) {
	sink := &memorySink{}
	rec := &fakeRecorder{blockAt: 2}
	m := NewMonitor(discardLogger(), rec, sink)
	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	m.now = func() time.Time { return fixed }
	r := requestWithContext()

	m.Report(r, EventAuthFailure, 401, "credenciais inválidas")
	if len(sink.events) != 1 {
		t.Fatalf("eventos = %d, esperado 1", len(sink.events))
	}
	e := sink.events[0]
	if e.Time != fixed || e.RequestID != "req-1" || e.ClientIP != "203.0.113.7" || e.ClientID != "app-pix" ||
		e.Method != "POST" || e.Path != "/oauth/token" || e.Status != 401 || e.Severity != SeverityWarning {
		t.Errorf("evento montado errado: %+v", e)
	}

	// A 2ª falha "bloqueia": deve surgir também o evento ip_block_triggered.
	m.Report(r, EventTokenInvalid, 401, "x")
	if len(sink.events) != 3 || sink.events[2].Type != EventIPBlockTriggered || sink.events[2].Severity != SeverityCritical {
		t.Fatalf("ip_block_triggered ausente: %+v", sink.events)
	}

	// Eventos que NÃO são falha não alimentam o bloqueio.
	m.Report(r, EventTokenIssued, 200, "")
	m.Report(r, EventRateLimited, 429, "")
	if len(rec.calls) != 2 {
		t.Errorf("RecordFailure chamado %d vezes, esperado 2", len(rec.calls))
	}
}

func TestMonitorRecorderError(t *testing.T) {
	sink := &memorySink{}
	m := NewMonitor(discardLogger(), &fakeRecorder{err: errors.New("redis fora")}, sink)
	m.Report(requestWithContext(), EventAuthFailure, 401, "")
	if len(sink.events) != 1 {
		t.Error("o evento deve ser registrado mesmo se o contador falhar")
	}
}

func TestMonitorWithoutRecorder(t *testing.T) {
	sink := &memorySink{}
	NewMonitor(discardLogger(), nil, sink).Report(requestWithContext(), EventAuthFailure, 401, "")
	if len(sink.events) != 1 {
		t.Error("evento não registrado")
	}
}

func TestTruncate(t *testing.T) {
	if truncate("abc", 5) != "abc" {
		t.Error("string curta não pode ser alterada")
	}
	long := strings.Repeat("é", 400) // 800 bytes, 2 bytes por caractere
	out := truncate(long, 511)       // corta no meio de um caractere
	if !utf8.ValidString(out) || !strings.HasSuffix(out, "...[truncado]") {
		t.Errorf("truncamento gerou UTF-8 inválido: %q", out[len(out)-20:])
	}
}

func TestSlogSinkEscapesInjection(t *testing.T) {
	var buf bytes.Buffer
	sink := NewSlogSink(slog.New(slog.NewJSONHandler(&buf, nil)))
	sink.Write(Event{Type: EventPathRejected, Severity: SeverityCritical, Path: "/x\n{\"falso\":true}"})
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("log injection: o evento gerou %d linhas", len(lines))
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil || m["level"] != "ERROR" {
		t.Errorf("linha inválida ou nível errado: %s", lines[0])
	}
}

func TestSeverityOf(t *testing.T) {
	if severityOf(EventTokenIssued) != SeverityInfo || severityOf(EventInfraError) != SeverityCritical ||
		severityOf(EventScopeDenied) != SeverityWarning {
		t.Error("severidades incorretas")
	}
}

// TestPostgresSinkIntegration usa um PostgreSQL real. Só roda se a variável
// TEST_DATABASE_URL estiver definida (no CI, ela aponta para um contêiner).
func TestPostgresSinkIntegration(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL não definida; teste de integração ignorado")
	}
	ctx := context.Background()
	sink, err := NewPostgresSink(ctx, url, 10, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	marker := "teste-" + time.Now().Format("150405.000000000")
	// Tentativa de SQL injection no path: deve ser gravada como texto literal.
	sink.Write(Event{Time: time.Now(), Type: EventPathRejected, Severity: SeverityWarning,
		RequestID: marker, Path: "/'; DROP TABLE security_events; --"})
	sink.Close() // Close grava o que estava na fila

	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var path string
	if err := conn.QueryRow(ctx, "SELECT path FROM security_events WHERE request_id = $1", marker).Scan(&path); err != nil {
		t.Fatalf("evento não encontrado: %v", err)
	}
	if path != "/'; DROP TABLE security_events; --" {
		t.Errorf("path gravado = %q", path)
	}
}

func TestPostgresSinkDropsWhenFull(t *testing.T) {
	// Sem conexão real: monta o sink "na mão" só para testar a fila.
	s := &PostgresSink{queue: make(chan Event, 1)}
	s.Write(Event{})
	s.Write(Event{}) // fila cheia: descarta sem bloquear
	if s.Dropped() != 1 {
		t.Errorf("Dropped = %d, esperado 1", s.Dropped())
	}
}

func TestNewPostgresSinkInvalidURL(t *testing.T) {
	_, err := NewPostgresSink(context.Background(), "postgres://u:senha-secreta@host:notaport/db", 1, discardLogger())
	if err == nil || strings.Contains(err.Error(), "senha-secreta") {
		t.Fatalf("erro deve existir e não pode vazar a senha: %v", err)
	}
}
