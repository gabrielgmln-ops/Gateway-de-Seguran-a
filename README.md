# Gateway de Segurança

Gateway de API em Go que fica **na frente** dos serviços internos **Ledger**, **Pix** e **Antifraude**.
Toda requisição externa passa por ele, que autentica, autoriza, limita, registra e só então encaminha.

> Projeto acadêmico. Todos os dados, clientes e segredos são **sintéticos**.

## Arquitetura

```
                         ┌──────────────────────── rede interna (Docker) ────────────────────────┐
 cliente ──HTTP──▶ :8080 │  GATEWAY                                                              │
                         │   1. RequestID ─ 2. IP real ─ 3. Access log ─ 4. Recover ─ 5. Headers │
                         │   6. IP bloqueado? ─ 7. Rate limit IP ─ 8. Path seguro ─ 9. Corpo máx. │
                         │                                                                       │
                         │   /oauth/token, /oauth/introspect  (rate limit OAuth por IP)          │
                         │   /ledger/*  /pix/*  /antifraude/*                                    │
                         │      └─ JWT válido ─ rate limit por cliente ─ escopo ─ reverse proxy ─┼─▶ ledger | pix | antifraude
                         │                                                                       │
                         │   Redis: token buckets + contadores/bloqueios de IP                   │
                         │   PostgreSQL: tabela security_events                                  │
                         └───────────────────────────────────────────────────────────────────────┘
```

Só o gateway publica porta. Os serviços internos, o Redis e o PostgreSQL ficam inacessíveis de fora.

## Defesas × OWASP API Security Top 10 (2023)

| Risco | Defesa no gateway | Onde |
|---|---|---|
| **API1** Broken Object Level Authorization | Identidade validada repassada em `X-Gateway-Client-ID` (cabeçalhos `X-Gateway-*` vindos do cliente são apagados), para o serviço checar a posse do objeto | `internal/proxy` |
| **API2** Broken Authentication | OAuth2 client_credentials; JWT HS256 com `alg` fixo, `typ=at+jwt`, `iss`/`aud`/`exp` obrigatórios; segredos como SHA-256 com comparação em tempo constante; anti-enumeração; bloqueio de IP após N falhas; rate limit no `/oauth` | `internal/auth`, `internal/ipblock` |
| **API3** Broken Object Property Level Authorization | Erros genéricos; introspecção inválida responde só `{"active":false}`; token não é repassado aos serviços | `internal/auth`, `internal/httpx` |
| **API4** Unrestricted Resource Consumption | Token bucket distribuído (IP, OAuth, cliente); limite de corpo; timeouts de servidor (Slowloris) e de upstream; fila de logs limitada | `internal/ratelimit`, `internal/server`, `cmd/gateway` |
| **API5** Broken Function Level Authorization | Lista fechada de rotas por serviço, cada uma com seu escopo (`read`/`write`); negar por padrão; bloqueio de `..` e barras codificadas | `internal/authz`, `internal/server` |
| **API6** Unrestricted Access to Sensitive Business Flows | Limite por cliente nas operações (ex.: disparo de Pix) e trilha de auditoria | `internal/ratelimit`, `internal/seclog` |
| **API7** Server Side Request Forgery | Destinos fixos validados na inicialização; o cliente nunca escolhe a URL; proxy de ambiente desativado | `internal/config`, `internal/proxy` |
| **API8/API2** Credencial de serviço | O `Authorization` do cliente é apagado e o gateway apresenta a **própria** credencial (HTTP Basic) aos serviços que exigem login; a senha nunca vai para log; 401 do serviço vira 502 genérico | `internal/config`, `internal/proxy` |
| **API8** Security Misconfiguration | Fail fast na configuração; cabeçalhos de segurança; remoção de `Server`/`X-Powered-By`; distroless não-root; contêineres read-only e sem capabilities | `internal/httpx`, `Dockerfile`, `docker-compose.yml` |
| **API9** Improper Inventory Management | Inventário único de rotas (`policies.go`); `/actuator`, Swagger e `/painel` dos serviços dão 404 genérico | `internal/authz/policies.go` |
| **API10** Unsafe Consumption of APIs | Timeouts e erros do upstream tratados sem vazar detalhes; cabeçalhos do upstream saneados | `internal/proxy` |

## Como rodar

### Pré-requisitos
- Go 1.26 ou superior (testado com 1.27.3)
- Docker e Docker Compose v2 (testado com Docker 29.8 no Windows 11)
- Sem Go instalado, os testes rodam num contêiner:
  `docker run --rm -v "$(pwd -W):/src" -w /src golang:1.27 go test -race ./...` (Git Bash)
- `openssl` e `sha256sum` (para gerar o `.env`)

### Com Docker Compose
```bash
./scripts/gerar-env.sh        # cria .env e .clientes-demo.env (permissão 600, fora do git)
docker compose up --build -d
docker compose ps             # gateway, redis e postgres devem aparecer como "healthy"
curl -s localhost:8083/readyz # {"postgres":"up","redis":"up"}
```

> O `.env` gerado publica o gateway na porta **8083** do host (`GATEWAY_HOST_PORT`),
> porque 8080 a 8082 costumam estar ocupadas por outros projetos. Nos exemplos abaixo,
> troque `8080` por `8083` se estiver usando o Compose.
> No Windows, rode os scripts `.sh` pelo **Git Bash** (já traz `openssl` e `sha256sum`).
> O `make` é opcional: cada alvo do `Makefile` é só um atalho para os comandos `go`/`docker`.

### Demonstração rápida
```bash
source .clientes-demo.env

# 1) Emitir token (OAuth2 client_credentials)
TOKEN=$(curl -s -u "app-leitura:$APP_LEITURA_SECRET" -d grant_type=client_credentials \
  localhost:8080/oauth/token | sed -E 's/.*"access_token":"([^"]+)".*/\1/')

# 2) Leitura permitida (200) e escrita negada por escopo (403)
curl -s -H "Authorization: Bearer $TOKEN" localhost:8080/ledger/api/v1/contas/1
curl -s -X POST -H "Authorization: Bearer $TOKEN" localhost:8080/pix/api/v1/pagamentos

# 2b) Rotas internas dos serviços não existem do lado de fora (404)
curl -s -H "Authorization: Bearer $TOKEN" localhost:8080/ledger/actuator/env

# 3) Validar o token (introspecção exige o escopo token:introspect)
curl -s -u "servico-validador:$SERVICO_VALIDADOR_SECRET" --data-urlencode "token=$TOKEN" \
  localhost:8080/oauth/introspect

# 4) Bloqueio de IP: 5 falhas e até o segredo correto é recusado (403 ip_blocked)
for i in 1 2 3 4 5; do curl -s -o /dev/null -w "%{http_code} " -u "app-pix:errado" \
  -d grant_type=client_credentials localhost:8080/oauth/token; done; echo

# 5) Eventos de segurança gravados
make eventos

# Para liberar o IP antes de expirar (15 min):
docker compose exec redis sh -c 'redis-cli -a "$REDIS_PASSWORD" --no-auth-warning --scan --pattern "ipblock:*" | xargs -r redis-cli -a "$REDIS_PASSWORD" --no-auth-warning del'
```

### Sem Docker (desenvolvimento)
É preciso ter Redis e (opcionalmente) PostgreSQL locais. Sem `DATABASE_URL`, os eventos vão só para o stdout.
```bash
make build
SERVICE_NAME=ledger MOCK_ADDR=:9001 ./bin/mockservice &
SERVICE_NAME=pix MOCK_ADDR=:9002 ./bin/mockservice &
SERVICE_NAME=antifraude MOCK_ADDR=:9003 ./bin/mockservice &
set -a; source .env; set +a
./bin/gateway
```

## Testes
```bash
make test        # todos os testes
make test-race   # com detector de condição de corrida
make cover       # cobertura + coverage.html

# Integração com PostgreSQL real (opcional):
TEST_DATABASE_URL="postgres://usuario:senha@localhost:5432/banco_teste?sslmode=disable" make cover
```
O Redis é simulado nos testes com o **miniredis**, que executa os scripts Lua de verdade.
O CI (`.github/workflows/ci.yml`) roda gofmt, go vet, govulncheck, os testes com `-race` em Go 1.26 e 1.27, com PostgreSQL real, e exige cobertura mínima de 80%.

## Endpoints

| Método | Rota | Autenticação | Descrição |
|---|---|---|---|
| GET | `/healthz` | — | Liveness (o processo está vivo) |
| GET | `/readyz` | — | Readiness (Redis e PostgreSQL respondem) |
| POST | `/oauth/token` | Basic ou formulário (client_id/secret) | Emite access token (RFC 6749 §4.4) |
| POST | `/oauth/introspect` | Cliente com escopo `token:introspect` | Valida token (RFC 7662) |
| * | `/ledger/*`, `/pix/*`, `/antifraude/*` | Bearer JWT + escopo da rota | Proxy para o serviço (só rotas da lista abaixo) |

### Rotas expostas (`internal/authz/policies.go`)

O caminho depois do prefixo é o do serviço real: `GET /ledger/api/v1/contas/1` chega à Ledger como
`GET /api/v1/contas/1`. `*` é um segmento (um id, uma chave). Fora desta lista: **404**; caminho certo
com método errado: **405**; escopo ausente: **403**.

| Serviço | `:read` | `:write` |
|---|---|---|
| `ledger` | `GET /api/v1/contas/*`, `/contas/*/extrato`, `/transferencias/*`, `/auditoria` | `POST /api/v1/contas`, `/depositos`, `/transferencias` |
| `pix` | `GET /api/v1/chaves`, `/chaves/*`, `/qrcodes/imagem`, `/pagamentos/*`, `/pagamentos/*/devolucoes`; `POST /api/v1/qrcodes/leitura` e `/leitura/imagem` (só decodificam) | `POST /api/v1/chaves`, `DELETE /chaves/*`, `POST /qrcodes`, `/pagamentos`, `/pagamentos/end-to-end-id`, `/pagamentos/*/devolucoes`, `/pagamentos/*/devolucoes/id` |
| `antifraude` | `GET /decisoes`, `/metricas` | — |

## Configuração

Todas as variáveis estão documentadas em [`.env.example`](.env.example). Segredos (`JWT_SECRET`,
`OAUTH_CLIENTS`, `REDIS_PASSWORD`, `POSTGRES_PASSWORD`) **só** por variável de ambiente.
Para cadastrar um cliente novo:
```bash
SEGREDO=$(openssl rand -hex 32)
printf '%s' "$SEGREDO" | go run ./cmd/hashsecret   # vai em "secret_sha256" no OAUTH_CLIENTS
```

### Ligar aos serviços reais

Por padrão, o Compose encaminha para os mocks. Para usar os projetos reais rodando no host, descomente no `.env`:
```bash
COMPOSE_LEDGER_URL=http://host.docker.internal:8081
COMPOSE_PIX_URL=http://host.docker.internal:8082
COMPOSE_ANTIFRAUDE_URL=http://host.docker.internal:8000
LEDGER_USUARIO=<conta de serviço criada na Ledger só para o gateway>
LEDGER_SENHA=<senha dessa conta>
```
O Pix Simulado também exige HTTP Basic: use `PIX_USUARIO`/`PIX_SENHA`. Qualquer serviço aceita `<SERVIÇO>_USUARIO`/`<SERVIÇO>_SENHA`; é preciso definir os dois ou nenhum, senão o
gateway não sobe. Se o serviço recusar a credencial, o cliente recebe 502 e o log mostra
`credencial de serviço recusada pelo upstream` com o usuário (nunca a senha).

Com os três serviços no ar, o teste de fumaça faz 25 verificações (contas, depósito, chave Pix, pagamento
liquidado na Ledger, rotas invisíveis, escopos negados):
```bash
bash scripts/fumaca-servicos-reais.sh   # 29/10/2026: 25 OK, 0 falha
```

## Estrutura
```
cmd/gateway        ponto de entrada (inclui o subcomando "healthcheck")
cmd/mockservice    serviço interno falso com dados sintéticos
cmd/hashsecret     gera o hash SHA-256 de um client_secret
internal/config    leitura e validação das variáveis de ambiente
internal/httpx     erros JSON, contexto (request id, IP, cliente) e cabeçalhos de segurança
internal/auth      clientes OAuth2, JWT, /oauth/token, /oauth/introspect, middleware Bearer
internal/authz     autorização por rota e escopo; policies.go é o inventário de rotas
internal/ratelimit token bucket no Redis (script Lua atômico)
internal/ipblock   contagem de falhas e bloqueio temporário de IP
internal/clientip  resolução do IP real com proxies confiáveis
internal/seclog    eventos de segurança: stdout (JSON) e PostgreSQL (assíncrono, em lote)
internal/proxy     reverse proxy endurecido
internal/server    roteador chi e middlewares
```

## Decisões e limitações conhecidas
- **HS256** (chave simétrica) porque o próprio gateway emite e valida os tokens. Se outros serviços
  precisarem validar, o próximo passo é RS256/EdDSA com JWKS e rotação de chave (`kid`).
- **Sem revogação** de token antes do `exp`. Mitigação: TTL curto (15 min). O `jti` já é emitido, e uma
  denylist no Redis seria a evolução natural.
- **Falha fechada**: se o Redis cair, o gateway responde 503 (`REDIS_FAIL_OPEN=false`). É uma escolha de
  segurança acima de disponibilidade, apropriada para fluxos financeiros.
- **BOLA (API1)** só se resolve por completo no serviço dono do dado. O gateway entrega a identidade confiável.
- **Uma conta de serviço por upstream:** para a Ledger, todos os clientes do gateway aparecem como o mesmo
  usuário. A verificação de posse precisa passar a usar o `X-Gateway-Client-ID`, e a conta de serviço deve ter
  o menor papel possível (a `/auditoria` só funciona se ela tiver permissão de operador).
- **HTTP Basic sem TLS** entre gateway e Ledger só é aceitável em rede local; em produção, `https://` no `LEDGER_URL`.
- **IPv6**: o bloqueio é por endereço exato. Em produção, considere agregar por prefixo /64.
- O PostgreSQL é acessado com `sslmode=disable` apenas porque está numa rede interna isolada. Em produção,
  use TLS (`verify-full`) e um usuário com permissão somente de `INSERT`.
