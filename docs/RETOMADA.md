# Retomada do projeto: Gateway de Segurança

Nota de passagem da sessão do Claude Code na nuvem (28/10/2026) para a sessão no PC Windows.

## Estado atual

**As Etapas 0 a 6 estão prontas** (0 a 5 testadas na nuvem; 6 no PC, em 29/10/2026). O código compila em Go 1.26 e 1.27, e os testes
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
| Docs | Retomada com o 1º CI | `e35cc86` |
| Docs | CI verde, Docker testado no Windows, desbloqueio de IP corrigido | `501133e` |
| 6 | Integração com serviços reais: rotas permitidas por serviço e credencial de serviço | `ee63d4e` |
| Teste | Teste de fumaça com Ledger, Pix e Antifraude reais (25/25) | último commit |

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
2. ~~**Docker não testado**~~ ✅ testado no PC em 28/10/2026 (Docker 29.8): gateway, redis e postgres `healthy`
   sem mudar nada do endurecimento (Redis com `user: redis` + `read_only` funcionou). `/readyz` respondeu
   `{"postgres":"up","redis":"up"}` na porta 8083 e a demonstração do README passou inteira (200, 403 de escopo,
   introspecção ativa, bloqueio de IP na 5ª falha, eventos em `security_events`).
   - O Go não está instalado no Windows; o `go test -race ./...` rodou verde no contêiner `golang:1.27`.
   - O comando de desbloqueio de IP do README não passava a senha do Redis (`NOAUTH`); corrigido.
3. ~~**CI no GitHub Actions**~~ ✅ o run do `e35cc86` ficou todo verde: qualidade (com govulncheck), testes 1.26 e
   1.27 e build Docker. O run do `d50332b` aparece como cancelado porque o seguinte o substituiu.
4. ~~Actions v7~~ ✅ funcionaram, nada a reverter.
5. **Autoria dos 6 primeiros commits:** estão como `Claude <noreply@anthropic.com>`; só os últimos têm o autor Gabriel. O push já foi feito, então padronizar agora reescreve o histórico e exige `git push --force-with-lease` (decisão do senhor):
   `git rebase -r --root --exec "git commit --amend --no-edit --reset-author"` (com `user.name`/`user.email` já configurados).
6. ~~**Integração com os serviços reais**~~ ✅ Etapa 6 (29/10/2026), aprovada pelo senhor antes de codar:
   - `internal/authz/policies.go` é o inventário único: 7 rotas da Ledger, 14 do Pix e 2 do Antifraude, cada
     uma com seu escopo. O resto dá 404 (`/actuator`, Swagger, `/saude`, `/painel`); método errado, 405.
   - `POST /pix/api/v1/qrcodes/leitura` e `/leitura/imagem` exigem só `pix:read` (só decodificam; exceção aprovada).
   - `<SERVIÇO>_USUARIO`/`<SERVIÇO>_SENHA` (os dois ou nenhum). O proxy apaga o `Authorization` do cliente e
     injeta o Basic de serviço; 401 do upstream com credencial vira 502 e um log com o usuário (sem a senha).
   - Compose: `COMPOSE_LEDGER_URL` etc. trocam os mocks pelos serviços reais em `host.docker.internal`.
   - Testado: `go test -race` verde (authz 100%, proxy 96%, config 96,8%) e Compose com mocks (rotas novas;
     Basic sintético chegou só à Ledger; senha ausente dos logs).
   - ✅ **Teste de fumaça com os serviços reais: 25/25** (29/10/2026), com `scripts/fumaca-servicos-reais.sh`.
     O Pix também exige HTTP Basic: recebeu `PIX_USUARIO`/`PIX_SENHA` sem mudança de código. Conta de serviço
     usada: a sintética "cliente" da Ledger (papel mínimo; a `/auditoria` responde 403, como esperado).
     Achados: o bloqueio de IP pegou o próprio teste na 2ª execução (o roteiro agora zera os contadores) e o
     `.env` do Pix aponta a Ledger para `localhost`, o que quebra no Docker (subir com
     `LEDGER_BASE_URL=http://host.docker.internal:8081 docker compose up -d`).
   - **Falta:** criar na Ledger uma conta de serviço própria para o gateway.
   - **Risco aceito:** todos os clientes aparecem para a Ledger como a mesma conta. A Ledger ainda não lê o
     `X-Gateway-Client-ID`; enquanto isso, a posse dos objetos (BOLA) não é checada por cliente.
7. ~~**Vault**~~ ✅ projeto (e o Pix Simulado, que faltava) no `MOC Projetos.md` em 28/10/2026.
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
