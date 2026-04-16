package types

import (
    "crypto"
    "time"
)

// CAConfig содержит конфигурацию для создания Root CA
type CAConfig struct {
    Subject       string
    KeyType       string
    KeySize       int
    Passphrase    []byte
    OutDir        string
    ValidityDays  int
    LogFile       string
}

// CAFiles содержит пути к созданным файлам
type CAFiles struct {
    PrivateKeyPath string
    CertPath       string
    PolicyPath     string
}

// CertificateInfo содержит информацию о сертификате
type CertificateInfo struct {
    Subject     string
    Serial      string
    NotBefore   time.Time
    NotAfter    time.Time
    KeyAlgo     string
    KeySize     int
}

// PublicKeyGetter - интерфейс для получения публичного ключа
type PublicKeyGetter interface {
    GetPublicKey() crypto.PublicKey
}

// CertificateTemplate определяет шаблон для создания сертификатов
type CertificateTemplate struct {
    Name         string
    KeyUsage     int
    ExtKeyUsage  []int
    IsCA         bool
    Description  string
}

// IntermediateCAConfig конфигурация для Intermediate CA
type IntermediateCAConfig struct {
    Subject          string
    KeyType          string
    KeySize          int
    Passphrase       []byte
    OutDir           string
    ValidityDays     int
    RootCAPassphrase []byte
    RootCADir        string
    MaxPathLen       int
}