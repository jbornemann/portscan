package net

import (
	"net/http"
	"time"
)

//DefaultHttpClient returns an http.Client with sane defaults
func DefaultHttpClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
	}
}
