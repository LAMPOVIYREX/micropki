```markdown
# MicroPKI

Минимальная реализация Public Key Infrastructure (PKI) для образовательных целей.

## Описание

MicroPKI - учебный проект, демонстрирующий основные концепции PKI:

- Создание самоподписанного Root CA
- Создание Intermediate CA, подписанного Root CA
- Генерация и шифрование ключей (RSA 4096, ECC P-384)
- Работа с X.509 сертификатами и шаблонами
- Безопасное хранение ключей с затиранием паролей в памяти
- База данных SQLite для хранения сертификатов
- Certificate Revocation List (CRL) для отзыва сертификатов
- OCSP Responder для проверки статуса в реальном времени (RFC 6960)
- Клиентские инструменты: генерация CSR, запрос сертификатов, валидация цепочек
- HTTP репозиторий для доступа к сертификатам, CRL и OCSP
- Аудит с криптографической целостностью (JSON + hash chain)
- Rate limiting для защиты от DDoS
- Certificate Transparency симуляция
- Компрометация ключей с блокировкой повторного использования

## Требования

- Go 1.21 или выше
- SQLite3
- Make (опционально)
- OpenSSL (для проверки)

## Установка

```bash
git clone https://github.com/LAMPOVIYREX/micropki.git
cd micropki
go mod download
make build
```

## Архитектура

```
                    ┌─────────────────┐
                    │   CLI (micropki) │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
        ▼                    ▼                    ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│   CA Module   │    │  Repository   │    │     OCSP      │
│ (Root/Int CA) │    │   Server      │    │  Responder    │
└───────┬───────┘    └───────┬───────┘    └───────┬───────┘
        │                    │                    │
        ▼                    ▼                    ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│   Database    │    │   Audit Log   │    │    CRL        │
│   (SQLite)    │    │   (JSON+hash) │    │   (PEM)       │
└───────────────┘    └───────────────┘    └───────────────┘
```

## Команды

### Root CA

```bash
# Создать Root CA
./micropki ca init \
    --subject "/CN=Root CA" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file pass.txt \
    --out-dir ./pki
```

### Intermediate CA

```bash
# Создать Intermediate CA
./micropki ca init-intermediate \
    --subject "/CN=Intermediate CA" \
    --out-dir ./pki-intermediate \
    --root-ca-dir ./pki \
    --root-passphrase-file pass.txt \
    --passphrase-file pass.txt
```

### База данных

```bash
# Инициализировать БД
./micropki db init --db-path ./pki/micropki.db

# Список сертификатов
./micropki db list --db-path ./pki/micropki.db
```

### Отзыв сертификатов (CRL)

```bash
# Отозвать сертификат
./micropki ca revoke "SERIAL" --reason keyCompromise --ca-dir ./pki-intermediate --ca-type intermediate --passphrase-file pass.txt

# Сгенерировать CRL
./micropki ca gen-crl --ca root --ca-dir ./pki --passphrase-file pass.txt
```

### OCSP Responder

```bash
# Выпустить OCSP сертификат
./micropki ca issue-ocsp-cert \
    --ca-cert ./pki-intermediate/certs/intermediate.cert.pem \
    --ca-key ./pki-intermediate/private/intermediate.key.pem \
    --ca-pass-file pass.txt \
    --subject "CN=OCSP Responder"

# Запустить OCSP responder
./micropki ocsp serve \
    --port 8081 \
    --responder-cert ./pki/certs/ocsp.cert.pem \
    --responder-key ./pki/certs/ocsp.key.pem \
    --ca-cert ./pki-intermediate/certs/intermediate.cert.pem
```

### Клиентские инструменты

```bash
# Создать CSR
./micropki client gen-csr \
    --subject "CN=test.example.com" \
    --out-key key.pem \
    --out-csr req.pem

# Отправить CSR на сервер
curl -X POST http://localhost:8080/request-cert \
    --data-binary @req.pem \
    --output cert.pem

# Проверить цепочку сертификата
./micropki client validate \
    --cert cert.pem \
    --trusted ./pki/certs/ca.cert.pem \
    --untrusted ./pki-intermediate/certs/intermediate.cert.pem

# Проверить статус сертификата
./micropki client check-status \
    --cert cert.pem \
    --ca-cert ./pki-intermediate/certs/intermediate.cert.pem
```

### Аудит

```bash
# Просмотр аудит-лога
./micropki audit query --level AUDIT --format table

# Проверка целостности
./micropki audit verify
```

### Компрометация ключа

```bash
# Скомпрометировать сертификат
./micropki ca compromise --cert cert.pem --reason keyCompromise --force
```

### HTTP репозиторий с rate limiting

```bash
./micropki repo serve \
    --port 8080 \
    --db-path ./pki/micropki.db \
    --cert-dir ./pki/certs \
    --rate-limit 10 \
    --rate-burst 20 \
    --ca-passphrase-file pass.txt
```

## API Endpoints

| Endpoint | Метод | Описание |
|----------|-------|----------|
| `/health` | GET | Проверка здоровья |
| `/certificate/{serial}` | GET | Получить сертификат |
| `/ca/root` | GET | Получить Root CA |
| `/ca/intermediate` | GET | Получить Intermediate CA |
| `/crl?ca=root` | GET | Получить CRL |
| `/request-cert` | POST | Отправить CSR |

## Демо

```bash
make demo
```

Демо-скрипт автоматически:
1. Создаёт Root и Intermediate CA
2. Выпускает server и client сертификаты
3. Запускает репозиторий
4. Проверяет цепочку и статус

## Тестирование

```bash
# Все тесты
make test

# Тесты производительности (1000 сертификатов)
make perf-test

# Покрытие кода
make coverage
```

## Makefile команды

| Команда | Описание |
|---------|----------|
| `make build` | Собрать проект |
| `make test` | Запустить тесты |
| `make perf-test` | Тест производительности |
| `make coverage` | Отчёт о покрытии |
| `make clean` | Очистить |
| `make demo` | Запустить демо |
| `make run-rsa` | Создать RSA Root CA |
| `make run-intermediate` | Создать Intermediate CA |
| `make db-init` | Инициализировать БД |
| `make repo-serve` | Запустить репозиторий |
| `make list-certs` | Показать сертификаты |

## Структура проекта

```
micropki/
├── cmd/
│   └── micropki/
│       └── main.go
├── internal/
│   ├── audit/          # Аудит с hash chain (Sprint 7)
│   ├── ca/             # CA операции (Sprint 1-2)
│   ├── certs/          # Работа с сертификатами
│   ├── cli/            # CLI команды
│   ├── client/         # Клиентские инструменты (Sprint 6)
│   ├── compromise/     # Компрометация ключей (Sprint 7)
│   ├── crl/            # CRL (Sprint 4)
│   ├── crypto/         # Криптография
│   ├── database/       # SQLite (Sprint 3)
│   ├── logger/         # Логирование
│   ├── ocsp/           # OCSP responder (Sprint 5)
│   ├── policy/         # Политики безопасности (Sprint 7)
│   ├── ratelimit/      # Rate limiting (Sprint 7)
│   ├── repository/     # HTTP сервер (Sprint 3)
│   ├── revocation/     # Проверка статуса (Sprint 6)
│   ├── serial/         # Генерация серийных номеров
│   ├── transparency/   # CT симуляция (Sprint 7)
│   └── validation/     # Валидация цепочек (Sprint 6)
├── pkg/
│   └── types/
├── tests/
├── demo/
├── Makefile
└── README.md
```

## Безопасность

- **Root/Intermediate CA ключи** – зашифрованы AES-256, права 0600
- **End-entity ключи** – предупреждение: хранятся незашифрованными
- **Passphrase** – затираются в памяти после использования
- **Rate limiting** – защита от DDoS (token bucket)
- **Audit** – JSON + SHA-256 hash chain, обнаружение подделки
- **CT симуляция** – append-only лог всех выпущенных сертификатов
- **Компрометация** – блокировка повторного использования ключа
- **Защита от timing attacks** – crypto/subtle

## Ограничения

- End-entity ключи хранятся незашифрованными
- OCSP responder использует HTTP (не HTTPS)
- CT симуляция без Merkle tree
- Rate limiting не защищает от распределённых атак
- Аудит не подписывается внешней подписью
- Проект образовательный, не для production

## Лицензия

MIT
```