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

CLIENTS=$(cat <<JSON
[{"client_id":"app-ledger","secret_sha256":"$(sha "$SEC_LEDGER")","scopes":["ledger:read","ledger:write"]},{"client_id":"app-pix","secret_sha256":"$(sha "$SEC_PIX")","scopes":["pix:read","pix:write"]},{"client_id":"app-antifraude","secret_sha256":"$(sha "$SEC_ANTIFRAUDE")","scopes":["antifraude:read","antifraude:write"]},{"client_id":"app-leitura","secret_sha256":"$(sha "$SEC_LEITURA")","scopes":["ledger:read","pix:read"]},{"client_id":"servico-validador","secret_sha256":"$(sha "$SEC_VALIDADOR")","scopes":["token:introspect"]}]
JSON
)

# umask 077: os arquivos nascem legíveis só pelo dono (permissão 600).
umask 077

cat > .env <<ENV
# Gerado por scripts/gerar-env.sh em $(date -u +%Y-%m-%dT%H:%M:%SZ). NÃO VERSIONAR.
GATEWAY_ADDR=:8080
LEDGER_URL=http://localhost:9001
PIX_URL=http://localhost:9002
ANTIFRAUDE_URL=http://localhost:9003
MAX_BODY_BYTES=1048576
UPSTREAM_TIMEOUT=10s
JWT_SECRET=$(rand)
JWT_ISSUER=gateway-seguranca
JWT_AUDIENCE=servicos-internos
JWT_TTL=15m
OAUTH_CLIENTS='${CLIENTS}'
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
