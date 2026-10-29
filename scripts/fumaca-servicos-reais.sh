#!/usr/bin/env bash
# Caminho: scripts/fumaca-servicos-reais.sh
#
# Teste de fumaça do gateway contra os serviços REAIS: Ledger API (8081),
# Pix Simulado (8082) e Motor Antifraude (8000), todos rodando no host.
#
# Pré-requisitos:
#   - os três serviços no ar;
#   - no .env do gateway: COMPOSE_*_URL apontando para host.docker.internal,
#     LEDGER_USUARIO/LEDGER_SENHA e PIX_USUARIO/PIX_SENHA (conta de serviço);
#   - docker compose up -d (gateway na porta GATEWAY_HOST_PORT, padrão 8083).
#
# Uso (Git Bash): bash scripts/fumaca-servicos-reais.sh
# Os segredos vêm de .clientes-demo.env e nunca são impressos.
set -u
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
source .clientes-demo.env
G="localhost:${GATEWAY_HOST_PORT:-8083}"
J='Content-Type: application/json'
ok=0; falhou=0
TMP=$(mktemp -d)

confere() { # nome esperado obtido
  if [ "$2" = "$3" ]; then echo "  OK    $1 ($3)"; ok=$((ok+1)); else echo "  FALHA $1: esperado $2, veio $3"; falhou=$((falhou+1)); fi
}
# campo lê um campo do JSON da entrada padrão, como no e2e do Pix Simulado.
campo() { python -c "import json,sys,decimal; d=json.load(sys.stdin, parse_float=decimal.Decimal); print(d$1)" 2>/dev/null; }
token() { curl -s -u "$1:$2" -d grant_type=client_credentials "$G/oauth/token" | campo "['access_token']"; }
# req TOKEN MÉTODO CAMINHO [corpo] -> imprime o status; o corpo fica em $TMP/corpo
req() {
  local t=$1 m=$2 p=$3; shift 3
  curl -s -o "$TMP/corpo" -w '%{http_code}' -X "$m" ${t:+-H "Authorization: Bearer $t"} -H "$J" \
    -H "Idempotency-Key: fumaca-$(date +%s%N)" ${1:+-d "$1"} "$G$p"
}
corpo() { cat "$TMP/corpo"; }

# O roteiro provoca 4 falhas de propósito (sem token e escopos negados), e o
# gateway bloqueia o IP na 5ª (IPBLOCK_MAX_FAILURES). Rodar duas vezes seguidas
# bloquearia o próprio teste, então ele começa zerando os contadores. Só faz
# sentido no ambiente local de teste; nunca rode isso em produção.
docker compose exec -T redis sh -c \
  'redis-cli -a "$REDIS_PASSWORD" --no-auth-warning --scan --pattern "ipblock:*" | xargs -r redis-cli -a "$REDIS_PASSWORD" --no-auth-warning del' >/dev/null

LEDGER=$(token app-ledger "$APP_LEDGER_SECRET")
PIX=$(token app-pix "$APP_PIX_SECRET")
AF=$(token app-antifraude "$APP_ANTIFRAUDE_SECRET")
LEITURA=$(token app-leitura "$APP_LEITURA_SECRET")

echo "1) Ledger real via gateway (credencial de serviço injetada)"
confere "sem token" 401 "$(req "" GET /ledger/api/v1/contas/x)"
confere "cria conta A (ledger:write)" 201 "$(req "$LEDGER" POST /ledger/api/v1/contas '{"titular":"Conta A Sintetica"}')"
CA=$(corpo | campo "['id']")
confere "cria conta B" 201 "$(req "$LEDGER" POST /ledger/api/v1/contas '{"titular":"Conta B Sintetica"}')"
CB=$(corpo | campo "['id']")
confere "depósito de R\$ 100 na conta A" 201 \
  "$(req "$LEDGER" POST /ledger/api/v1/depositos "{\"contaId\":\"$CA\",\"valor\":100.00,\"descricao\":\"Saldo inicial sintetico\"}")"
confere "consulta a conta A (ledger:read)" 200 "$(req "$LEITURA" GET "/ledger/api/v1/contas/$CA")"
confere "saldo da conta A" 100.00 "$(corpo | campo "['saldo']")"
confere "extrato da conta A" 200 "$(req "$LEITURA" GET "/ledger/api/v1/contas/$CA/extrato")"
confere "escrita com token só de leitura (API5)" 403 \
  "$(req "$LEITURA" POST /ledger/api/v1/depositos "{\"contaId\":\"$CA\",\"valor\":1.00}")"
confere "auditoria negada pela Ledger à conta de serviço (papel mínimo)" 403 "$(req "$LEDGER" GET /ledger/api/v1/auditoria)"
confere "actuator da Ledger invisível (API9)" 404 "$(req "$LEDGER" GET /ledger/actuator/health)"
confere "swagger da Ledger invisível" 404 "$(req "$LEDGER" GET /ledger/v3/api-docs)"
confere "método fora da lista" 405 "$(req "$LEDGER" DELETE "/ledger/api/v1/contas/$CA")"

echo "2) Pix real via gateway"
CHAVE="fumaca.$(date +%s)@exemplo.com"
confere "cadastra chave da conta B (pix:write)" 201 \
  "$(req "$PIX" POST /pix/api/v1/chaves "{\"tipo\":\"EMAIL\",\"valor\":\"$CHAVE\",\"contaId\":\"$CB\",\"titular\":{\"nome\":\"Conta B Sintetica\",\"cpf\":\"12345678909\"}}")"
confere "consulta a chave (pix:read)" 200 "$(req "$LEITURA" GET "/pix/api/v1/chaves/$CHAVE")"
confere "cadastro de chave com token só de leitura (API5)" 403 \
  "$(req "$LEITURA" POST /pix/api/v1/chaves '{"tipo":"EMAIL","valor":"x@exemplo.com"}')"
req "$PIX" POST /pix/api/v1/qrcodes "{\"chave\":\"$CHAVE\",\"valor\":25.90}" >/dev/null
QR=$(corpo | campo "['payload']")
confere "leitura de QR Code com pix:read (exceção aprovada)" 200 \
  "$(req "$LEITURA" POST /pix/api/v1/qrcodes/leitura "{\"payload\":\"$QR\"}")"
req "$PIX" POST /pix/api/v1/pagamentos/end-to-end-id >/dev/null
E2E=$(corpo | campo "['endToEndId']")
confere "Pix de R\$ 25,90 da conta A para a chave da conta B" 201 \
  "$(req "$PIX" POST /pix/api/v1/pagamentos "{\"endToEndId\":\"$E2E\",\"contaOrigemId\":\"$CA\",\"qrPayload\":\"$QR\"}")"
confere "pagamento liquidado na Ledger real" LIQUIDADO "$(corpo | campo "['estado']")"
confere "consulta o pagamento" 200 "$(req "$LEITURA" GET "/pix/api/v1/pagamentos/$E2E")"
req "$LEITURA" GET "/ledger/api/v1/contas/$CA" >/dev/null
confere "saldo da conta A após o Pix" 74.10 "$(corpo | campo "['saldo']")"
req "$LEITURA" GET "/ledger/api/v1/contas/$CB" >/dev/null
confere "saldo da conta B após o Pix" 25.90 "$(corpo | campo "['saldo']")"

echo "3) Motor Antifraude real via gateway"
confere "decisões (antifraude:read)" 200 "$(req "$AF" GET /antifraude/decisoes)"
confere "métricas" 200 "$(req "$AF" GET /antifraude/metricas)"
confere "painel HTML invisível (API9)" 404 "$(req "$AF" GET /antifraude/painel)"
confere "token sem escopo do Antifraude" 403 "$(req "$LEITURA" GET /antifraude/decisoes)"

echo
echo "Resultado: $ok OK, $falhou falha(s)"
rm -rf "$TMP"
[ "$falhou" -eq 0 ]
