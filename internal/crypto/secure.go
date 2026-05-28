package crypto

import (
    "crypto/rand"
    "encoding/binary"
    "runtime"
)

// SecureZero затирает данные в памяти
func SecureZero(data []byte) {
    if data == nil || len(data) == 0 {
        return
    }
    
    // Затираем каждый байт
    for i := range data {
        data[i] = 0
    }
    
    // Дополнительная защита: чтение из памяти чтобы предотвратить оптимизацию
    runtime.KeepAlive(data)
}

// SecureString затирает строку в памяти
func SecureString(s string) []byte {
    // Преобразуем в байты и затираем после использования
    b := []byte(s)
    defer SecureZero(b)
    return b
}

// SecureCompare постоянное сравнение для защиты от timing attacks
func SecureCompare(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }
    
    var result byte = 0
    for i := 0; i < len(a); i++ {
        result |= a[i] ^ b[i]
    }
    return result == 0
}

// GenerateSecureRandom генерирует криптостойкие случайные байты
func GenerateSecureRandom(length int) ([]byte, error) {
    bytes := make([]byte, length)
    _, err := rand.Read(bytes)
    return bytes, err
}

// SecureUint64 генерирует безопасное случайное число
func SecureUint64() (uint64, error) {
    var buf [8]byte
    _, err := rand.Read(buf[:])
    if err != nil {
        return 0, err
    }
    return binary.LittleEndian.Uint64(buf[:]), nil
}