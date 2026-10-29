package gateway

import "time"

// ShortenConnectionAge lets a test watch a connection outlive its client certificate.
func ShortenConnectionAge(age, grace time.Duration) (restore func()) {
	oldAge, oldGrace := connectionAge, connectionAgeGrace
	connectionAge, connectionAgeGrace = age, grace
	return func() { connectionAge, connectionAgeGrace = oldAge, oldGrace }
}
