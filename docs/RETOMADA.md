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
| Docs | Nota de retomada | `6fed510` |
| Docs | Repositório publicado no GitHub | `4f079b6` |
| Fix | `golang.org/x/text` v0.43.0 (vulnerabilidade apontada pelo govulncheck) e actions v7 | `d50332b` |
| Docs | Esta atualização da nota | último commit |

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

1. ~~**GitHub**~~ ✅ publicado em 28/10/2026 em https://github.com/gabrielgmln-ops/Gateway-de-Seguran-a (branch `main`). O bundle `gateway-seguranca-backup.bundle` fica só como cópia de segurança.
2. **Docker não testado:** a nuvem não tinha daemon Docker. Rodar `docker compose up --build -d` no PC e conferir se gateway, redis e postgres ficam `healthy`. Os pontos de maior risco são o Redis com `user: redis` + `read_only` e o Postgres com volume.
3. **CI no GitHub Actions:** o 1º run (`4f079b6`) passou nos testes (Go 1.26 e 1.27), mas falhou no
   govulncheck por uma vulnerabilidade em `golang.org/x/text` v0.29.0 alcançável via pgx. O job docker foi pulado.
   Corrigido em `d50332b` (x/text v0.43.0 e actions v7). **Conferir se o 2º run ficou todo verde**, inclusive o
   build Docker, que ainda nunca rodou: `gh run list --repo gabrielgmln-ops/Gateway-de-Seguran-a`.
4. Se as actions v7 quebrarem algo no CI, voltar para a última versão que funcionar e registrar o motivo.
5. **Autoria dos 6 primeiros commits:** estão como `Claude <noreply@anthropic.com>`; só os últimos têm o autor Gabriel. O push já foi feito, então padronizar agora reescreve o histórico e exige `git push --force-with-lease` (decisão do senhor):
   `git rebase -r --root --exec "git commit --amend --no-edit --reset-author"` (com `user.name`/`user.email` já configurados).
6. **Integração com os serviços reais** (próximo passo de valor): apontar `LEDGER_URL`, `PIX_URL` e `ANTIFRAUDE_URL` para os projetos reais, por exemplo `http://host.docker.internal:8081`.
   - **Atenção:** a Ledger API recebeu HTTP Basic na Operação Cofre, e o gateway remove o `Authorization` antes de encaminhar. Será preciso decidir como o gateway se autentica em cada serviço, por exemplo com credenciais de serviço por variável de ambiente (`LEDGER_USUARIO` e `LEDGER_SENHA`) injetadas pelo proxy.
   - Mapear os escopos para as rotas reais (`/api/v1/...`).
7. **Vault:** acrescentar o projeto ao `MOC Projetos.md` (a nuvem não consegue editar arquivos existentes no Drive).
8. **Opcional:** texto para LinkedIn e currículo, e revisão com o professor.

## O que o senhor precisa fornecer

- Docker Desktop aberto e Go ≥ 1.26 (`go version`); se o Go for mais antigo, ele baixa a toolchain sozinho.
- Git Bash para rodar `./scripts/gerar-env.sh`, que gera um `.env` novo: os segredos da nuvem **não** foram salvos.
- Para a integração: as portas e as credenciais de teste da Ledger, do Pix e do Antifraude no PC.

## Como restaurar o código

Pelo GitHub (preferido):

```bash
git clone https://github.com/gabrielgmln-ops/Gateway-de-Seguran-a.git gateway-seguranca
```

Ou, sem internet, a partir do bundle (tem os 8 primeiros commits; falta só esta atualização da nota):

```bash
git clone gateway-seguranca-backup.bundle gateway-seguranca
cd gateway-seguranca
git remote set-url origin https://github.com/gabrielgmln-ops/Gateway-de-Seguran-a.git
git pull origin main
```
