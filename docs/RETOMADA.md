# Retomada do projeto: Gateway de Segurança

Nota de passagem da sessão do Claude Code na nuvem (28/10/2026) para a sessão no PC Windows.

## Estado atual

**As Etapas 0 a 5 estão prontas e testadas na nuvem.** O código compila em Go 1.26 e 1.27, e os testes
passam com o detector de corrida (`-race`). A cobertura é de 95,0% com PostgreSQL real e de 90,2% sem ele.

A validação de ponta a ponta foi feita na nuvem com os binários, Redis 7 e PostgreSQL 16 locais, **sem Docker**:

- token emitido e validado
- 200 com o escopo certo, 403 sem escopo, 401 sem token, 405 para TRACE, 413 para corpo de 2 MB
- 429 no rate limit, 503 com o Redis fora do ar (fail closed)
- bloqueio de IP após 5 falhas, com eventos gravados em `security_events`

## Etapas e commits

| Etapa | Escopo | Commit |
|---|---|---|
| 0 | Setup, reverse proxy, middlewares base, mock, Dockerfile, Compose | `4633ee4` |
| 1 | OAuth2 client_credentials, JWT HS256, `/oauth/token`, `/oauth/introspect` | `3c22dcd` |
| 2 | Autorização por escopo (`<serviço>:read\|write`, negar por padrão) | `d7679fa` |
| 3 | Token bucket no Redis (Lua atômico): IP, OAuth e cliente; `/readyz` | `89fc9b5` |
| 4 | Bloqueio de IP por falhas, IP real com proxies confiáveis, log no PostgreSQL | `e0c14a3` |
| 5 | Testes, cobertura, CI (gofmt, vet, govulncheck, matriz Go 1.26/1.27) | `5024007` |
| Ajuste | Portas configuráveis (8083), `.gitattributes` LF, notas para Windows | `3d815b3` |
| Docs | Esta nota de retomada | último commit |

## Decisões tomadas

- **Go 1.26 como mínimo**, porque o Go 1.24 pedido inicialmente já está sem suporte em 10/2026. O CI e o Dockerfile usam 1.27.
- **HS256**, porque o próprio gateway emite e valida os tokens. A evolução natural é RS256/EdDSA com JWKS.
- **Segredos de cliente com hash SHA-256** em vez de bcrypt: são segredos aleatórios de 32 bytes, e o bcrypt abriria um vetor de DoS por CPU.
- **O `Authorization` não segue para os serviços internos.** A identidade vai em `X-Gateway-Client-ID`, `X-Gateway-Scopes` e `X-Gateway-Token-ID`, e qualquer `X-Gateway-*` ou `X-Internal-*` enviado pelo cliente é apagado.
- **Fail closed:** com o Redis fora, as requisições recebem 503 (`REDIS_FAIL_OPEN=false`).
- **O `X-Forwarded-For` só vale vindo de `TRUSTED_PROXIES`** e é lido da direita para a esquerda.
- **Falhas que contam para o bloqueio de IP:** `auth_failure`, `token_invalid`, `scope_denied` e `path_rejected`. O rate limit não conta.
- **Log no PostgreSQL assíncrono e em lote**, com fila limitada. Quando a fila enche, o evento é descartado e contado, mas continua no stdout.
- **Porta do host 8083**, porque no PC as portas 8080 (AgentService), 8081 (Ledger API) e 8082 (Pix Simulado) estão ocupadas.

## Pendências

1. **GitHub:** criar o repositório vazio `gabrielgmln-ops/gateway-seguranca` e fazer o push. Até lá, o código existe só no bundle `gateway-seguranca-backup.bundle`.
2. **Docker não testado:** a nuvem não tinha daemon Docker. Rodar `docker compose up --build -d` no PC e conferir se gateway, redis e postgres ficam `healthy`. Os pontos de maior risco são o Redis com `user: redis` + `read_only` e o Postgres com volume.
3. **govulncheck não rodou:** o proxy da nuvem bloqueou `vuln.go.dev`. Ele vai rodar no primeiro CI.
4. **Primeiro CI no GitHub Actions** ainda não executado.
5. **Autoria dos 6 primeiros commits:** estão como `Claude <noreply@anthropic.com>`; só os dois últimos têm o autor Gabriel. Se o senhor quiser padronizar, reescreva a autoria **antes** do primeiro push (depois exigiria force push):
   `git rebase -r --root --exec "git commit --amend --no-edit --reset-author"` (com `user.name`/`user.email` já configurados).
6. **Integração com os serviços reais** (próximo passo de valor): apontar `LEDGER_URL`, `PIX_URL` e `ANTIFRAUDE_URL` para os projetos reais, por exemplo `http://host.docker.internal:8081`.
   - **Atenção:** a Ledger API recebeu HTTP Basic na Operação Cofre, e o gateway remove o `Authorization` antes de encaminhar. Será preciso decidir como o gateway se autentica em cada serviço, por exemplo com credenciais de serviço por variável de ambiente (`LEDGER_USUARIO` e `LEDGER_SENHA`) injetadas pelo proxy.
   - Mapear os escopos para as rotas reais (`/api/v1/...`).
7. **Vault:** acrescentar o projeto ao `MOC Projetos.md` (a nuvem não consegue editar arquivos existentes no Drive).
8. **Opcional:** texto para LinkedIn e currículo, e revisão com o professor.

## O que o senhor precisa fornecer

- O repositório vazio `gabrielgmln-ops/gateway-seguranca` no GitHub (sem README, sem licença), ou autorização para eu criá-lo pelo `gh`.
- Docker Desktop aberto e Go ≥ 1.26 (`go version`); se o Go for mais antigo, ele baixa a toolchain sozinho.
- Git Bash para rodar `./scripts/gerar-env.sh`, que gera um `.env` novo: os segredos da nuvem **não** foram salvos.
- Para a integração: as portas e as credenciais de teste da Ledger, do Pix e do Antifraude no PC.

## Como restaurar a partir do bundle

```bash
git clone gateway-seguranca-backup.bundle gateway-seguranca
cd gateway-seguranca
git remote remove origin
git log --oneline   # 8 commits, o último é "docs: nota de retomada da sessão"
```
