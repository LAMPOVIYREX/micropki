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
- OCSP Responder для проверки статуса в реальном времени
- Клиентские инструменты: генерация CSR, запрос сертификатов, валидация цепочек
- HTTP репозиторий для доступа к сертификатам, CRL и OCSP

## Требования

- Go 1.18 или выше
- SQLite3
- Make (опционально)
- OpenSSL (для проверки)

## Установка

```bash
git clone <repository-url>
cd micropki
go mod download
make build
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
./micropki ca revoke "SERIAL" --reason keyCompromise

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

### HTTP репозиторий

```bash
./micropki repo serve --port 8080 --db-path ./pki/micropki.db --cert-dir ./pki/certs
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

## Makefile команды

| Команда | Описание |
|---------|----------|
| `make build` | Собрать проект |
| `make test` | Запустить тесты |
| `make clean` | Очистить |
| `make run-rsa` | Создать RSA Root CA |
| `make run-intermediate` | Создать Intermediate CA |
| `make db-init` | Инициализировать БД |
| `make repo-serve` | Запустить репозиторий |
| `make list-certs` | Показать сертификаты |

## Структура проекта

```
micropki/
├── cmd/micropki/main.go
├── internal/
│   ├── ca/           # CA операции
│   ├── certs/        # Сертификаты
│   ├── cli/          # CLI команды
│   ├── crl/          # CRL (Sprint 4)
│   ├── crypto/       # Криптография
│   ├── database/     # SQLite
│   ├── logger/       # Логирование
│   ├── ocsp/         # OCSP (Sprint 5)
│   ├── repository/   # HTTP сервер
│   ├── validation/   # Валидация (Sprint 6)
│   ├── revocation/   # Проверка статуса (Sprint 6)
│   └── client/       # Клиентские инструменты (Sprint 6)
├── pkg/types/
├── tests/
├── Makefile
└── README.md
```
