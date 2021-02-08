package cli

import (
	"encoding/json"
	"github.com/jbornemann/portscan/pkg/types"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCommandLineArgs_PrepareSubmitRequest_MustProvideAHost(t *testing.T) {
	c := CommandLineArgs{
		ScanIPs:  []string{"35.10.100.103", "35.10.100.104"},
		ScanPort: "8080",
	}
	req, err := c.PrepareSubmitRequest()
	assert.Nil(t, req)
	assert.EqualError(t, err, "you must provide a pscan server host")
}

func TestCommandLineArgs_PrepareSubmitRequest_HostMustBeValid(t *testing.T) {
	c := CommandLineArgs{
		Host:     "'",
		ScanIPs:  []string{"35.10.100.103", "35.10.100.104"},
		ScanPort: "8080",
	}
	req, err := c.PrepareSubmitRequest()
	assert.Nil(t, req)
	assert.EqualError(t, err, "pscan server host is not valid")
}

func TestCommandLineArgs_PrepareSubmitRequest_MustProvideScanIPs(t *testing.T) {
	c := CommandLineArgs{
		Host:     "127.0.0.1",
		ScanPort: "8080",
	}
	req, err := c.PrepareSubmitRequest()
	assert.Nil(t, req)
	assert.EqualError(t, err, "you must provide a list of ips to scan")
}

func TestCommandLineArgs_PrepareSubmitRequest_MustProvideAScanPort(t *testing.T) {
	c := CommandLineArgs{
		Host:    "127.0.0.1",
		ScanIPs: []string{"35.10.100.103", "35.10.100.104"},
	}
	req, err := c.PrepareSubmitRequest()
	assert.Nil(t, req)
	assert.EqualError(t, err, "you must provide a port to scan")

	c.ScanPort = "oops"
	req, err = c.PrepareSubmitRequest()
	assert.Nil(t, req)
	assert.EqualError(t, err, "oops is not a valid port to scan")
}

func TestCommandLineArgs_PrepareSubmitRequest_WillAddDefaultScheme(t *testing.T) {
	c := CommandLineArgs{
		Host:     "127.0.0.1",
		ScanIPs:  []string{"35.10.100.103", "35.10.100.104"},
		ScanPort: "8080",
	}
	req, err := c.PrepareSubmitRequest()
	assert.Nil(t, err)
	assert.NotNil(t, req)
	assert.Equal(t, req.Host.Scheme, defaultScheme)
}

func TestCommandLineArgs_PrepareSubmitRequest(t *testing.T) {
	c := CommandLineArgs{
		Host:     "https://myserver.com",
		ScanIPs:  []string{"35.10.100.103", "35.10.100.104"},
		ScanPort: "8080",
	}
	req, err := c.PrepareSubmitRequest()
	assert.Nil(t, err)
	assert.NotNil(t, req)
}

func TestCommandLineArgs_PrepareQuery_MustProvideAHost(t *testing.T) {
	c := CommandLineArgs{
		ScanID: "123",
	}
	req, err := c.PrepareQuery()
	assert.Nil(t, req)
	assert.EqualError(t, err, "you must provide a pscan server host")
}

func TestCommandLineArgs_PrepareQuery_HostMustBeValid(t *testing.T) {
	c := CommandLineArgs{
		Host:   "'",
		ScanID: "123",
	}
	req, err := c.PrepareQuery()
	assert.Nil(t, req)
	assert.EqualError(t, err, "pscan server host is not valid")
}

func TestCommandLineArgs_PrepareQuery_WillAddDefaultScheme(t *testing.T) {
	c := CommandLineArgs{
		Host:   "127.0.0.1",
		ScanID: "123",
	}
	req, err := c.PrepareQuery()
	assert.Nil(t, err)
	assert.NotNil(t, req)
	assert.Equal(t, req.Host.Scheme, defaultScheme)
}

func TestSubmit(t *testing.T) {
	called := false
	scanRequest := types.ScanRequest{
		ScanIPs:  []string{"30.125.124.123"},
		ScanPort: 8080,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		bs, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var req types.ScanRequest
		err = json.Unmarshal(bs, &req)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !reflect.DeepEqual(req, scanRequest) {
			w.WriteHeader(http.StatusInternalServerError)
		}
		resp := types.ScanResponse{ScanID: 123}
		bs, err = json.Marshal(&resp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(bs)
	}))
	defer server.Close()

	client := server.Client()
	thisUrl, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	req := SubmitRequest{
		Host:        *thisUrl,
		ScanRequest: scanRequest,
	}
	err = Submit(req, client)
	assert.Nil(t, err)
	assert.True(t, called)
}

func TestQuery(t *testing.T) {
	called := false
	queryRequest := types.QueryRequest{
		ScanID: 123,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		bs, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var req types.QueryRequest
		err = json.Unmarshal(bs, &req)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !reflect.DeepEqual(req, queryRequest) {
			w.WriteHeader(http.StatusInternalServerError)
		}
		resp := types.QueryResponse{Ready: false}
		bs, err = json.Marshal(&resp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(bs)
	}))
	defer server.Close()

	client := server.Client()
	thisUrl, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	q := Query{
		Host:         *thisUrl,
		QueryRequest: queryRequest,
	}
	err = DoQuery(q, client)
	assert.Nil(t, err)
	assert.True(t, called)
}
