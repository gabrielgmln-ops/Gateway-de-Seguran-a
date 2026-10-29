#!/usr/bin/env bash
# Caminho: scripts/gerar-env.sh
#
# Gera um arquivo .env com segredos ALEATÓRIOS e clientes OAuth2 SINTÉTICOS.
# Os client_secrets em texto puro vão para .clientes-demo.env, usado só nos
# testes manuais com curl. No .env fica apenas o hash SHA-256 de cada um.
# Os dois arquivos estão no .gitignore.
#
# Uso: ./scripts/gerar-env.sh            (recusa sobrescrever um .env existente)
#      ./scripts/gerar-env.sh --force
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -f .env && "${1:-}" != "--force" ]]; then
  echo "O arquivo .env já existe. Use --force para sobrescrever." >&2
  exit 1
fi

rand() { openssl rand -hex 32; }
sha() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }

SEC_LEDGER=$(rand)
SEC_PIX=$(rand)
SEC_ANTIFRAUDE=$(rand)
SEC_LEITURA=$(rand)
SEC_VALIDADOR=$(rand)
PG_PASS=$(rand)

CLIENTS=$(cat <<JSON
[{"client_id":"app-ledger","secret_sha256":"$(sha "$SEC_LEDGER")","scopes":["ledger:read","ledger:write"]},{"client_id":"app-pix","secret_sha256":"$(sha "$SEC_PIX")","scopes":["pix:read","pix:write"]},{"client_id":"app-antifraude","secret_sha256":"$(sha "$SEC_ANTIFRAUDE")","scopes":["antifraude:read","antifraude:write"]},{"client_id":"app-leitura","secret_sha256":"$(sha "$SEC_LEITURA")","scopes":["ledger:read","pix:read"]},{"client_id":"servico-validador","secret_sha256":"$(sha "$SEC_VALIDADOR")","scopes":["token:introspect"]}]
JSON
)

# umask 077: os arquivos nascem legíveis só pelo dono (permissão 600).
umask 077

cat > .env <<ENV
# Gerado por scripts/gerar-env.sh em $(date -u +%Y-%m-%dT%H:%M:%SZ). NÃO VERSIONAR.
GATEWAY_ADDR=:8083
# Porta publicada no host pelo docker compose (8083 evita conflito com Ledger/Pix no PC)
GATEWAY_HOST_PORT=8083
LEDGER_URL=http://localhost:9001
PIX_URL=http://localhost:9002
ANTIFRAUDE_URL=http://localhost:9003
MAX_BODY_BYTES=1048576
UPSTREAM_TIMEOUT=10s
# --- Serviços reais (opcional) ---
# Sem estas linhas, o Compose usa os mocks da rede interna. Com elas, o gateway
# encaminha para os projetos reais rodando no host (portas do PC do autor).
#COMPOSE_LEDGER_URL=http://host.docker.internal:8081
#COMPOSE_PIX_URL=http://host.docker.internal:8082
#COMPOSE_ANTIFRAUDE_URL=http://host.docker.internal:8000
# Credencial de SERVIÇO que o gateway apresenta à Ledger (HTTP Basic). Use uma
# conta só para o gateway, nunca a de uma pessoa. Defina as duas ou nenhuma.
#LEDGER_USUARIO=
#LEDGER_SENHA=
JWT_SECRET=$(rand)
JWT_ISSUER=gateway-seguranca
JWT_AUDIENCE=servicos-internos
JWT_TTL=15m
OAUTH_CLIENTS='${CLIENTS}'
REDIS_ADDR=localhost:6379
REDIS_PASSWORD=$(rand)
REDIS_DB=0
REDIS_FAIL_OPEN=false
RATE_LIMIT_IP_CAPACITY=100
RATE_LIMIT_IP_REFILL_PER_SEC=50
RATE_LIMIT_OAUTH_CAPACITY=10
RATE_LIMIT_OAUTH_REFILL_PER_SEC=0.5
RATE_LIMIT_CLIENT_CAPACITY=20
RATE_LIMIT_CLIENT_REFILL_PER_SEC=10
IPBLOCK_MAX_FAILURES=5
IPBLOCK_WINDOW=10m
IPBLOCK_DURATION=15m
TRUSTED_PROXIES=
POSTGRES_PASSWORD=${PG_PASS}
DATABASE_URL=postgres://gateway:${PG_PASS}@localhost:5432/seguranca?sslmode=disable
SECLOG_BUFFER=1000
ENV

cat > .clientes-demo.env <<ENV
# Segredos SINTÉTICOS para testes manuais. NÃO VERSIONAR.
export APP_LEDGER_SECRET=${SEC_LEDGER}
export APP_PIX_SECRET=${SEC_PIX}
export APP_ANTIFRAUDE_SECRET=${SEC_ANTIFRAUDE}
export APP_LEITURA_SECRET=${SEC_LEITURA}
export SERVICO_VALIDADOR_SECRET=${SEC_VALIDADOR}
ENV

echo "Arquivos .env e .clientes-demo.env gerados (permissão 600)."
