package net

//ValidPort returns true if port is within a valid port range
func ValidPort(port uint) bool {
	return port > 0 && port < 65353
}
