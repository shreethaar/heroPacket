package middleware

// Constants for PCAP file validation
const (
	MaxPCAPSize = 100 * 1024 * 1024  // 100MB
	PCAPMagicLE = "\xd4\xc3\xb2\xa1" // Little-endian
	PCAPMagicBE = "\xa1\xb2\xc3\xd4" // Big-endian
	PCAPMagicNS = "\x4d\x3c\xb2\xa1" // Nanosecond precision
)

// If there's any CSRF configuration here, remove it completely
// Keep other middleware configurations intact

// Example:
// Remove any lines like:
// func ConfigureCSRF() echo.MiddlewareFunc {
//     return middleware.CSRF()
// }

// Or any CSRF-related constants or variables
