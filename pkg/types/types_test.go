package types

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestScanRequest_Validate_MustProvideListOfIPs(t *testing.T) {
	s := ScanRequest{
		ScanPort: 8080,
	}
	valid, err := s.Validate()
	assert.EqualError(t, err, "you must provide a list of ips")
	assert.False(t, valid)
}

func TestScanRequest_Validate_IPsMustBeValid(t *testing.T) {
	s := ScanRequest{
		ScanIPs: []string{
			"notanip",
			"127.0.0.1",
		},
		ScanPort: 8080,
	}
	valid, err := s.Validate()
	assert.False(t, valid)
	assert.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "not a valid ip address"))
}

func TestScanRequest_Validate_ScanPortMustBeInRange(t *testing.T) {
	s := ScanRequest{
		ScanIPs: []string{
			"80.10.34.10",
			"127.0.0.1",
		},
		ScanPort: 0,
	}
	valid, err := s.Validate()
	assert.False(t, valid)
	assert.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "not a valid port number"))

	s.ScanPort = 70000
	valid, err = s.Validate()
	assert.False(t, valid)
	assert.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "not a valid port number"))
}

func TestScanRequest_Validate(t *testing.T) {
	s := ScanRequest{
		ScanIPs: []string{
			"80.10.34.10",
			"127.0.0.1",
		},
		ScanPort: 8080,
	}
	valid, err := s.Validate()
	assert.True(t, valid)
	assert.Nil(t, err)
}
