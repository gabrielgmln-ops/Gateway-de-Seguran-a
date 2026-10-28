# Caminho: Makefile
# Atalhos para as tarefas do dia a dia. Uso: make <alvo>  (ex.: make test)
# Comparação com Python: é como os "scripts" de um pyproject/tox/nox.

.PHONY: help env build test test-race cover vet fmt up down logs eventos

help: ## lista os alvos disponíveis
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

env: ## gera o .env com segredos aleatórios e clientes sintéticos
	./scripts/gerar-env.sh

build: ## compila os binários em ./bin
	go build -o bin/gateway ./cmd/gateway
	go build -o bin/mockservice ./cmd/mockservice
	go build -o bin/hashsecret ./cmd/hashsecret

test: ## roda todos os testes
	go test ./...

test-race: ## roda os testes com o detector de condição de corrida
	go test -race ./...

cover: ## gera o relatório de cobertura (coverage.html)
	go test -covermode=atomic -coverprofile=coverage.out ./internal/...
	go tool cover -func=coverage.out | tail -1
	go tool cover -html=coverage.out -o coverage.html

vet: ## análise estática
	go vet ./...

fmt: ## formata o código
	gofmt -w .

up: ## sobe tudo com Docker Compose (requer .env)
	docker compose up --build -d

down: ## derruba os contêineres
	docker compose down

logs: ## acompanha os logs do gateway
	docker compose logs -f gateway

eventos: ## mostra os últimos eventos de segurança gravados no PostgreSQL
	docker compose exec postgres psql -U gateway -d seguranca -c \
	  "SELECT occurred_at, event_type, severity, client_ip, client_id, status, detail FROM security_events ORDER BY id DESC LIMIT 20"
