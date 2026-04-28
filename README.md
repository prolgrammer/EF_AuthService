# auth-service

Сервис аутентификации платформы **EventFlow**: выпуск и валидация JWT (RS256), управление пользователями, JWKS, ротация ключей подписи.

## TL;DR

```bash
cp .env.example .env
make up           # Postgres + auth-service в Docker
./scripts/smoke.sh
```

REST на `:8080`, gRPC на `:9090`, Prometheus на `:2112/metrics`.

## Архитектура

Слои изолированы по [hexagonal](https://alistair.cockburn.us/hexagonal-architecture/) принципу:

```
main → internal/app  ─┬─ internal/transport/httpsrv  (REST: /v1/auth/*, /jwks.json, /healthz, /readyz)
                      ├─ internal/transport/grpcsrv  (gRPC: Auth.Login/Refresh/ValidateToken/JWKS)
                      ├─ internal/service/auth       (use-cases, бизнес-логика)
                      ├─ internal/keystore           (RS256 ключи + ротация + JWKS)
                      ├─ internal/repository/postgres (pgx/v5)
                      └─ internal/observability      (Prometheus + OTel)
internal/domain  — чистые сущности и порты репозиториев (никаких зависимостей).
```

Граф зависимостей строго одного направления: `transport → service → domain ← repository`. Транспорт и репозиторий не знают друг о друге.

## REST API

Полная спецификация — в ТЗ §11.1.1; здесь ключевые контракты.

```
POST /v1/auth/register
{ "email": "...", "password": "..." } → 201 { "user_id": "..." }

POST /v1/auth/login
{ "email": "...", "password": "..." }
→ 200 { "access_token", "refresh_token", "token_type":"Bearer", "expires_in": 900 }

POST /v1/auth/refresh
{ "refresh_token": "..." }
→ 200 { "access_token", "refresh_token", "token_type":"Bearer", "expires_in": 900 }

POST /v1/auth/validate            # для api-gateway, если он не хочет JWT-парсить локально
{ "token": "..." }
→ 200 { "valid": true|false, "user_id", "expires_at", "scopes": [...] }

GET  /jwks.json                    # публичные ключи для оффлайн-валидации
GET  /healthz                       # liveness
GET  /readyz                        # readiness (DB ping)
```

Также метрики Prometheus отдаются на отдельном listener-е `:2112/metrics` — это bulkhead, чтобы тяжёлые HTTP-запросы не блокировали scrape.

### Коды ошибок

| HTTP | error                  | Когда                                                |
|------|------------------------|------------------------------------------------------|
| 400  | invalid_email          | email не парсится по RFC 5322                         |
| 400  | weak_password          | < 10 символов                                         |
| 401  | invalid_credentials    | email не существует или пароль неверный              |
| 401  | token_expired          | exp в прошлом                                         |
| 401  | token_revoked          | refresh уже ротирован — reuse-detection              |
| 401  | token_invalid          | подпись не сходится / kid неизвестен                  |
| 409  | email_taken            | unique violation на регистрации                       |
| 503  | not_ready              | DB ping упал                                          |

## gRPC API

Контракт в `proto/auth/v1/auth.proto`. Сгенерируй стабы:

```bash
make proto       # требует buf
make build TAGS=proto
```

Без флага `proto` сервис собирается, поднимает gRPC-сервер с `grpc_health_v1`, но AuthService не зарегистрирован (warning в логе). Это позволяет билду пройти до выполнения кодгена — удобно при первом клонировании.

## JWT и ключи

- **Алгоритм:** RS256 (RFC 7518). Алгоритм фиксирован при парсинге — `none`/HS256 атаки невозможны.
- **kid:** обязательный заголовок токена, маршрутизирует к нужному публичному ключу.
- **Ротация:** фоновая горутина в keystore раз в `AUTH_JWT_KEY_ROTATE_EVERY` (default 30d) генерирует новый ключ. Старый остаётся валидным для верификации ещё `AUTH_JWT_KEY_OVERLAP` (default 72h) — это чтобы access-токены, выпущенные до ротации, дожили свой 15-минутный TTL.
- **JWKS:** все активные публичные ключи отдаются на `/jwks.json` с `Cache-Control: max-age=300`.
- **Refresh-токен:** opaque-строка (base64url, 32 байта рандома), не JWT. В БД хранится только SHA-256 хеш — компрометация БД не выдаст рабочих токенов.
- **Refresh-rotation + reuse-detection:** при /refresh старая запись помечается `revoked` и связывается с новой через `replaced_by`. Повторный /refresh уже отозванным токеном считается атакой и каскадно отзывает все refresh-токены пользователя (RFC 6819 §5.2.2.3).
- **Ключи на диске:** `AUTH_JWT_KEY_DIR` (default `./keys`). PEM-пара `<kid>.pem` (private, 0600) + `<kid>.pub` (public, 0644). В compose замонтирован volume `authkeys`.

## Postgres

Схема — миграция `migrations/0001_init.sql` (см. ТЗ §13.1):

```sql
users           (id, email CITEXT UNIQUE, password_hash BYTEA, created_at, updated_at)
refresh_tokens  (id, user_id, token_hash UNIQUE, issued_at, expires_at, revoked_at, replaced_by)
```

Миграции применяются автоматически при `AUTH_DB_MIGRATE_ON_START=true` через [goose](https://github.com/pressly/goose).

## Observability

| Стенд | Что  |
|---|---|
| `:2112/metrics` | Prometheus: `http_requests_total`, `grpc_server_handled_total`, `auth_login_attempts_total{result}`, `auth_tokens_issued_total{kind}`, `auth_tokens_validated_total{result}`, `auth_key_rotations_total`, `auth_jwks_active_keys` + go/process |
| stdout | zap JSON-логи, поля `service`, `instance`, `request_id`, `trace_id`/`span_id` (когда включён OTel) |
| OTLP gRPC | OpenTelemetry-трейсинг (опционально, `AUTH_TRACING_ENABLED=true`) |

## Конфигурация

Все настройки — через ENV с префиксом `AUTH_`. См. `.env.example` (расшифрован построчно). Валидация выполняется на старте — сервис не поднимется с противоречивой конфигурацией (например, access-TTL ≥ refresh-TTL, или overlap ≥ rotate period).

## Локальная разработка

```bash
# Один Postgres, без Docker — например через psql:
createdb auth && createuser auth -W
export AUTH_DB_DSN="postgres://auth:auth@localhost:5432/auth?sslmode=disable"

cp .env.example .env
make tidy
make build              # без gRPC, быстро
make proto              # сгенерировать stubs (нужен buf)
make build TAGS=proto   # с gRPC
make run TAGS=proto
```

## Тестирование

```bash
make test               # unit с -race
make cover              # HTML coverage
```


