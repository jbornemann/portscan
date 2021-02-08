package server

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCommandLineArgs_ValidateAndPrepare_ListenPortMustBeProvided(t *testing.T) {
	args := CommandLineArgs{}
	config, err := args.ValidateAndPrepare()
	assert.Nil(t, config)
	assert.NotNil(t, err)
}

func TestCommandLineArgs_ValidateAndPrepare_ListenPortMustBeValid(t *testing.T) {
	args := CommandLineArgs{
		ListenPort: "junk",
	}
	config, err := args.ValidateAndPrepare()
	assert.Nil(t, config)
	assert.NotNil(t, err)

	args = CommandLineArgs{
		ListenPort: "-3",
	}
	config, err = args.ValidateAndPrepare()
	assert.Nil(t, config)
	assert.NotNil(t, err)
}

func TestCommandLineArgs_ValidateAndPrepare(t *testing.T) {
	args := CommandLineArgs{
		ListenPort: "8080",
	}
	config, err := args.ValidateAndPrepare()
	assert.Nil(t, err)
	assert.NotNil(t, config)
	assert.Equal(t, uint(8080), config.ListenPort)
}
