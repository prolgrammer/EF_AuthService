# Makefile auth-service

GO       ?= go
BUF      ?= buf
PKG      := ./...
BIN      := ./bin/auth-service
TAGS     ?=

.PHONY: help
help:
	@grep -E '^[a-zA-Z0-9_\-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ---------- Code generation ----------
.PHONY: proto
proto: ## Сгенерировать gRPC/proto код в pkg/pb/
	@$(BUF) generate
	@echo "✅ proto generated. Build with: make build TAGS=proto"

.PHONY: lint
lint: ## golangci-lint + buf lint
	golangci-lint run
	@$(BUF) lint || true

.PHONY: tidy
tidy: ## go mod tidy
	$(GO) mod tidy

# ---------- Build & run ----------
.PHONY: build
build: ## Собрать бинарник (TAGS=proto чтобы включить gRPC)
	CGO_ENABLED=0 $(GO) build -tags "$(TAGS)" -trimpath -ldflags="-s -w" -o $(BIN) .

.PHONY: run
run: ## Запустить сервис локально (использует .env если есть)
	$(GO) run -tags "$(TAGS)" .

# ---------- Tests ----------
.PHONY: test
test: ## Юнит-тесты
	$(GO) test -race -count=1 -cover -coverprofile=coverage.out $(PKG)

.PHONY: cover
cover: test ## Открыть HTML coverage
	$(GO) tool cover -html=coverage.out

.PHONY: bench
bench: ## Бенчмарки
	$(GO) test -bench=. -benchmem -run=^$$ $(PKG)

# ---------- Docker / compose ----------
.PHONY: docker-build
docker-build: ## Собрать образ (--build-arg BUILD_TAGS=proto если нужен gRPC)
	docker build --build-arg BUILD_TAGS=$(TAGS) -t auth-service:dev .

.PHONY: up
up: ## Поднять Postgres + auth-service
	docker compose up --build -d

.PHONY: down
down: ## Остановить compose
	docker compose down

.PHONY: logs
logs: ## Логи compose
	docker compose logs -f --tail=100

# ---------- DB ----------
.PHONY: psql
psql: ## Открыть psql внутри compose-контейнера
	docker compose exec postgres psql -U auth -d auth

.PHONY: migrate-up
migrate-up: ## Накатить миграции локально (используется goose)
	@goose -dir migrations postgres "$$AUTH_DB_DSN" up

.PHONY: migrate-down
migrate-down:
	@goose -dir migrations postgres "$$AUTH_DB_DSN" down

# ---------- Smoke (требует jq, curl) ----------
.PHONY: smoke
smoke: ## Регистрация + login + refresh + validate против localhost:8080
	@./scripts/smoke.sh
