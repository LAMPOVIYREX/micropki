
# MicroPKI

Минимальная реализация Public Key Infrastructure (PKI) для образовательных целей.

## Описание

MicroPKI - это учебный проект, демонстрирующий основные концепции PKI:

- Создание самоподписанного Root CA
- Создание Intermediate CA, подписанного Root CA
- Генерация и шифрование ключей (RSA 4096, ECC P-384)
- Работа с X.509 сертификатами и шаблонами
- Безопасное хранение ключей с затиранием паролей в памяти
- База данных SQLite для хранения сертификатов
- Certificate Revocation List (CRL) для отзыва сертификатов
- OCSP Responder для проверки статуса в реальном времени
- HTTP репозиторий для доступа к сертификатам, CRL и OCSP
- Подробное логирование всех операций

## Требования

- Go 1.21 или выше (рекомендуется) / Go 1.18 (минимальная)
- SQLite3
- Make (опционально)
- OpenSSL (для проверки сертификатов)

## Установка

```bash
# Клонировать репозиторий
git clone <repository-url>
cd micropki

# Скачать зависимости
go mod download

# Собрать проект
make build
# или
go build -o micropki cmd/micropki/main.go
```

## Использование

### 1. Инициализация Root CA

```bash
# Создать файл с паролем
echo "MySecure-Passphrase-2024" > passphrase.txt
chmod 600 passphrase.txt

# Создать RSA Root CA
./micropki ca init \
    --subject "/CN=MicroPKI Root CA/O=MicroPKI/C=RU" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file passphrase.txt \
    --out-dir ./pki \
    --validity-days 3650
```

### 2. Создание Intermediate CA

```bash
./micropki ca init-intermediate \
    --subject "/CN=Intermediate CA/O=MicroPKI/C=RU" \
    --key-type rsa \
    --key-size 4096 \
    --out-dir ./pki-intermediate \
    --root-ca-dir ./pki \
    --root-passphrase-file passphrase.txt \
    --passphrase-file passphrase.txt \
    --max-path-len 1
```

### 3. Управление базой данных сертификатов

```bash
# Инициализация базы данных
./micropki db init --db-path ./pki/micropki.db

# Просмотр всех сертификатов
./micropki db list --db-path ./pki/micropki.db

# Просмотр в JSON формате
./micropki db list --format json --db-path ./pki/micropki.db

# Получение сертификата по серийному номеру
./micropki db show 2A7F... --db-path ./pki/micropki.db
```

### 4. Отзыв сертификатов и генерация CRL

```bash
# Отзыв сертификата
./micropki ca revoke "SERIAL_NUMBER" \
    --reason keyCompromise \
    --db-path ./pki/micropki.db

# Генерация CRL для Root CA
./micropki ca gen-crl \
    --ca root \
    --ca-dir ./pki \
    --passphrase-file passphrase.txt \
    --db-path ./pki/micropki.db

# Генерация CRL для Intermediate CA
./micropki ca gen-crl \
    --ca intermediate \
    --ca-dir ./pki-intermediate \
    --passphrase-file passphrase.txt \
    --db-path ./pki/micropki.db \
    --next-update 14
```

### 5. OCSP Responder

```bash
# Выпустить сертификат для OCSP responder
./micropki ca issue-ocsp-cert \
    --ca-cert ./pki-intermediate/certs/intermediate.cert.pem \
    --ca-key ./pki-intermediate/private/intermediate.key.pem \
    --ca-pass-file passphrase.txt \
    --subject "CN=OCSP Responder,O=MicroPKI" \
    --key-type rsa \
    --key-size 4096 \
    --san localhost \
    --out-dir ./pki/certs \
    --validity-days 365

# Запустить OCSP responder
./micropki ocsp serve \
    --host 127.0.0.1 \
    --port 8081 \
    --db-path ./pki/micropki.db \
    --responder-cert ./pki/certs/ocsp.cert.pem \
    --responder-key ./pki/certs/ocsp.key.pem \
    --ca-cert ./pki-intermediate/certs/intermediate.cert.pem \
    --cache-ttl 120
```

### 6. Запуск HTTP репозитория

```bash
./micropki repo serve \
    --host 127.0.0.1 \
    --port 8080 \
    --db-path ./pki/micropki.db \
    --cert-dir ./pki/certs
```

## API Endpoints

| Endpoint | Метод | Описание |
|----------|-------|----------|
| `/health` | GET | Проверка здоровья сервера |
| `/certificate/{serial}` | GET | Получение сертификата по серийному номеру |
| `/ca/root` | GET | Получение Root CA сертификата |
| `/ca/intermediate` | GET | Получение Intermediate CA сертификата |
| `/crl?ca=root` | GET | Получение Root CRL |
| `/crl?ca=intermediate` | GET | Получение Intermediate CRL |

### OCSP API

| Метод | Формат | Пример |
|-------|--------|--------|
| GET | параметр `serial` | `curl "http://localhost:8081/?serial=2222222222222222"` |
| POST | form-data | `curl -X POST -d "serial=2222222222222222" http://localhost:8081/` |
| POST | JSON | `curl -X POST -H "Content-Type: application/json" -d '{"serial":"2222222222222222"}' http://localhost:8081/` |

**Ответы OCSP:**
- `good` - сертификат валидный
- `revoked` - сертификат отозван
- `unknown` - сертификат не найден

## Проверка с OpenSSL

```bash
# Просмотр сертификата
openssl x509 -in ./pki/certs/ca.cert.pem -text -noout

# Проверка сертификата
openssl verify -CAfile ./pki/certs/ca.cert.pem ./pki/certs/ca.cert.pem

# Проверка цепочки
openssl verify -CAfile ./pki/certs/ca.cert.pem \
    ./pki-intermediate/certs/intermediate.cert.pem

# Просмотр CRL
openssl crl -in ./pki/crl/root.crl.pem -inform PEM -text -noout
```

## Структура проекта

```
micropki/
├── cmd/
│   └── micropki/
│       └── main.go
├── internal/
│   ├── ca/                     # CA операции
│   │   ├── ca.go
│   │   └── intermediate.go
│   ├── certs/                  # Работа с сертификатами
│   │   ├── certificate.go
│   │   ├── templates.go
│   │   └── verify.go
│   ├── cli/                    # CLI интерфейс
│   │   └── cli.go
│   ├── crl/                    # CRL операции (Sprint 4)
│   │   ├── generator.go
│   │   └── revoke.go
│   ├── crypto/                 # Криптографические операции
│   │   ├── crypto.go
│   │   ├── secure.go
│   │   └── constant_time.go
│   ├── database/               # База данных
│   │   ├── schema.go
│   │   └── cert_store.go
│   ├── logger/                 # Логирование
│   │   └── logger.go
│   ├── ocsp/                   # OCSP responder (Sprint 5)
│   │   └── responder.go
│   └── repository/             # HTTP репозиторий
│       └── server.go
├── pkg/
│   └── types/
│       └── types.go
├── tests/
│   ├── ca_test.go
│   └── integration_test.go
├── Makefile
├── go.mod
├── go.sum
└── README.md
```

## Результат работы

```
pki/
├── private/
│   └── ca.key.pem               # Зашифрованный ключ Root CA
├── certs/
│   ├── ca.cert.pem              # Сертификат Root CA
│   └── ocsp.cert.pem            # Сертификат OCSP responder
├── crl/
│   └── root.crl.pem             # CRL Root CA
├── micropki.db                  # База данных SQLite
└── policy.txt

pki-intermediate/
├── private/
│   └── intermediate.key.pem     # Зашифрованный ключ Intermediate CA
├── certs/
│   ├── intermediate.cert.pem    # Сертификат Intermediate CA
│   └── chain.cert.pem           # Полная цепочка
└── crl/
    └── intermediate.crl.pem     # CRL Intermediate CA
```

## Команды Makefile

| Команда | Описание |
|---------|----------|
| `make build` | Собрать проект |
| `make test` | Запустить тесты |
| `make clean` | Очистить сгенерированные файлы |
| `make run-rsa` | Создать RSA Root CA |
| `make run-ecc` | Создать ECC Root CA |
| `make run-intermediate` | Создать Intermediate CA |
| `make db-init` | Инициализировать базу данных |
| `make repo-serve` | Запустить HTTP репозиторий |
| `make list-certs` | Показать все сертификаты |
| `make help` | Показать все команды |

## Особенности реализации

### Безопасность
- Приватные ключи хранятся в зашифрованном виде (PKCS#8, AES-256)
- Права доступа: private/ (0700), ключи (0600)
- Затирание паролей в памяти после использования
- Защита от timing attacks (crypto/subtle)
- Проверка качества паролей (мин. 8 символов, uppercase, lowercase, digit)

### Стандарты
- X.509 v3 сертификаты с правильными расширениями
- CRLv2 согласно RFC 5280
- OCSP согласно RFC 6960

### База данных
- SQLite с уникальными серийными номерами
- Индексы для быстрого поиска

### Логирование
- Подробное логирование всех операций
- ISO 8601 timestamp с миллисекундами
- HTTP access log с префиксом [HTTP]

## Зависимости

### Внешние Go модули
| Пакет | Версия | Назначение |
|-------|--------|------------|
| github.com/spf13/cobra | v1.7.0 | CLI фреймворк |
| github.com/spf13/viper | v1.16.0 | Управление конфигурацией |
| github.com/stretchr/testify | v1.8.4 | Тестирование |
| github.com/youmark/pkcs8 | v0.0.0-20201027041543-1326539a0a0a | PKCS#8 шифрование |
| github.com/mattn/go-sqlite3 | v1.14.22 | Драйвер SQLite |

## Реализованные спринты

| Спринт | Описание | Статус |
|--------|----------|--------|
| 1 | Foundation & Root CA | ✅ |
| 2 | Intermediate CA & Templates | ✅ |
| 3 | Certificate Management & Repository | ✅ |
| 4 | Revocation System (CRL) | ✅ |
| 5 | OCSP Responder | ✅ |

## Планы на следующие спринты

- Sprint 6: Path Validation & Client Tools
- Sprint 7: Security Hardening & Audit
- Sprint 8: Integration & Demo Scenario
