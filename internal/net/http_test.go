package net

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDefaultHttpClient_Sanity(t *testing.T) {
	assert.NotNil(t, DefaultHttpClient())
}
