// Caminho: internal/seclog/seclog.go
//
// Pacote seclog: log de SEGURANÇA estruturado (OWASP API10, e base para
// detectar ataques em geral). É separado do access log: aqui só entram
// eventos relevantes para auditoria (falha de login, token inválido etc.).
package seclog

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"gateway-seguranca/internal/httpx"
)

// EventType é um "tipo nomeado" baseado em string. Em Python, seria parecido
// com uma classe Enum(str): o compilador impede passar uma string qualquer por engano.
type EventType string

// Catálogo de eventos de segurança. "const ( ... )" agrupa constantes.
const (
	EventTokenIssued      EventType = "token_issued"       // token emitido com sucesso
	EventAuthFailure      EventType = "auth_failure"       // client_id/secret inválidos
	EventAuthMissing      EventType = "auth_missing"       // requisição sem token
	EventTokenInvalid     EventType = "token_invalid"      // token expirado, adulterado etc.
	EventScopeDenied      EventType = "scope_denied"       // token válido, mas sem o escopo exigido
	EventRateLimited      EventType = "rate_limited"       // excedeu o limite de requisições
	EventIPBlocked        EventType = "ip_blocked"         // requisição de IP já bloqueado
	EventIPBlockTriggered EventType = "ip_block_triggered" // IP acabou de ser bloqueado
	EventPathRejected     EventType = "path_rejected"      // path traversal / caminho malicioso
	EventInfraError       EventType = "infra_error"        // Redis indisponível etc.
)

// Severidades usadas para filtrar e alertar.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Limites de tamanho dos campos: um atacante não pode inflar os logs
// enviando caminhos ou cabeçalhos gigantes (OWASP API4).
const (
	maxPathLen   = 512
	maxDetailLen = 512
)

// Event é um evento de segurança. As tags json definem o nome no log.
type Event struct {
	Time      time.Time `json:"time"`
	Type      EventType `json:"event_type"`
	Severity  string    `json:"severity"`
	RequestID string    `json:"request_id"`
	ClientIP  string    `json:"client_ip"`
	ClientID  string    `json:"client_id,omitempty"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Status    int       `json:"status"`
	Detail    string    `json:"detail,omitempty"`
}

// Sink é qualquer destino de eventos (stdout, PostgreSQL...).
//
// Comparação com Python: interfaces em Go são satisfeitas IMPLICITAMENTE.
// Basta um tipo ter o método Write(Event) para "ser" um Sink, sem precisar
// declarar herança (como o duck typing do Python, só que verificado na compilação).
type Sink interface {
	Write(e Event)
}

// Reporter é o que os middlewares e handlers usam para relatar eventos.
// Depender de uma interface (e não do tipo concreto) facilita os testes.
type Reporter interface {
	Report(r *http.Request, t EventType, status int, detail string)
}

// FailureRecorder conta falhas por IP. É implementado pelo ipblock.Blocker
// (Etapa 4). Devolve true quando o IP acabou de ser bloqueado.
type FailureRecorder interface {
	RecordFailure(ctx context.Context, ip string) (bool, error)
}

// Monitor implementa Reporter: monta o evento, envia a todos os sinks e,
// se for uma falha de segurança, alimenta o contador de bloqueio de IP.
type Monitor struct {
	sinks    []Sink
	failures FailureRecorder // pode ser nil (sem bloqueio de IP)
	logger   *slog.Logger
	now      func() time.Time // função injetável: nos testes, um relógio fixo
}

// NewMonitor cria o monitor. "sinks ...Sink" é um parâmetro variádico,
// equivalente a "*sinks" no Python.
func NewMonitor(logger *slog.Logger, failures FailureRecorder, sinks ...Sink) *Monitor {
	return &Monitor{sinks: sinks, failures: failures, logger: logger, now: time.Now}
}

// countsAsFailure define quais eventos contam para o bloqueio de IP.
// Rate limit não conta: ele já tem resposta própria (429).
func countsAsFailure(t EventType) bool {
	switch t {
	case EventAuthFailure, EventTokenInvalid, EventScopeDenied, EventPathRejected:
		return true
	}
	return false
}

func severityOf(t EventType) string {
	switch t {
	case EventTokenIssued, EventAuthMissing:
		return SeverityInfo
	case EventIPBlockTriggered, EventInfraError:
		return SeverityCritical
	default:
		return SeverityWarning
	}
}

// Report registra o evento. O método tem um "receiver" (m *Monitor):
// é o equivalente ao "self" dos métodos de classe do Python.
func (m *Monitor) Report(r *http.Request, t EventType, status int, detail string) {
	ctx := r.Context()
	ev := Event{
		Time:      m.now().UTC(),
		Type:      t,
		Severity:  severityOf(t),
		RequestID: httpx.RequestIDFrom(ctx),
		ClientIP:  httpx.ClientIPFrom(ctx),
		ClientID:  httpx.ClientIDFrom(ctx),
		Method:    r.Method,
		Path:      truncate(r.URL.Path, maxPathLen),
		Status:    status,
		Detail:    truncate(detail, maxDetailLen),
	}
	m.emit(ev)

	if m.failures == nil || !countsAsFailure(t) || ev.ClientIP == "" {
		return
	}
	// context.WithoutCancel: mesmo que o cliente desconecte, a falha precisa ser contada.
	// Sem isso, o atacante poderia abortar a conexão para escapar do bloqueio.
	recCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	blocked, err := m.failures.RecordFailure(recCtx, ev.ClientIP)
	if err != nil {
		m.logger.Error("falha ao registrar tentativa para bloqueio de IP", "error", err.Error())
		return
	}
	if blocked {
		trig := ev // cópia da struct (structs são copiadas por valor, diferente de objetos Python)
		trig.Type = EventIPBlockTriggered
		trig.Severity = severityOf(EventIPBlockTriggered)
		trig.Detail = "limite de falhas atingido; IP bloqueado temporariamente"
		m.emit(trig)
	}
}

func (m *Monitor) emit(ev Event) {
	for _, s := range m.sinks {
		s.Write(ev)
	}
}

// truncate corta a string em n bytes sem quebrar caracteres UTF-8 no meio.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Recua até o início de um caractere UTF-8 válido (bytes de continuação são 10xxxxxx).
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n] + "...[truncado]"
}

// SlogSink escreve os eventos como JSON no stdout (coletável por qualquer SIEM).
type SlogSink struct {
	logger *slog.Logger
}

// NewSlogSink cria o sink de stdout.
func NewSlogSink(logger *slog.Logger) *SlogSink {
	return &SlogSink{logger: logger}
}

// Write implementa a interface Sink.
func (s *SlogSink) Write(e Event) {
	level := slog.LevelWarn
	switch e.Severity {
	case SeverityInfo:
		level = slog.LevelInfo
	case SeverityCritical:
		level = slog.LevelError
	}
	// O handler JSON do slog escapa aspas e quebras de linha: isso impede
	// "log injection" (forjar linhas falsas de log via campos do usuário).
	s.logger.Log(context.Background(), level, "security_event",
		"event_type", string(e.Type),
		"severity", e.Severity,
		"request_id", e.RequestID,
		"client_ip", e.ClientIP,
		"client_id", e.ClientID,
		"method", e.Method,
		"path", e.Path,
		"status", e.Status,
		"detail", e.Detail,
	)
}
