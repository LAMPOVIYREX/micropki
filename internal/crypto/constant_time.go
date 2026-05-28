package crypto

import (
    "crypto/subtle"
)

// ConstantTimeCompare безопасное сравнение строк
func ConstantTimeCompare(a, b string) bool {
    return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ConstantTimeBytesCompare безопасное сравнение байтов
func ConstantTimeBytesCompare(a, b []byte) bool {
    return subtle.ConstantTimeCompare(a, b) == 1
}