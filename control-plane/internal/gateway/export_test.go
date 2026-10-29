package gateway

import "time"

// ShortenConnectionAge lets a test watch a connection outlive its client certificate.
func ShortenConnectionAge(age, grace time.Duration) (restore func()) {
	oldAge, oldGrace := connectionAge, connectionAgeGrace
	connectionAge, connectionAgeGrace = age, grace
	return func() { connectionAge, connectionAgeGrace = oldAge, oldGrace }
}

// RecheckEvery lets a test see rewritten files at the next handshake or call.
func RecheckEvery(d time.Duration) (restore func()) {
	old := recheckEvery
	recheckEvery = d
	return func() { recheckEvery = old }
}
