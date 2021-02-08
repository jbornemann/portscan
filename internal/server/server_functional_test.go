// +build integration

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/jbornemann/portscan/pkg/types"
	"github.com/stretchr/testify/assert"
	"io"
	"io/ioutil"
	"net/http"
	"testing"
	"time"
)

func TestServer(t *testing.T) {
	port := uint(8080)
	server := NewServer(Configuration{ListenPort: port})
	kill := make(chan bool)
	go server.Run(kill)
	t.Cleanup(func() {
		kill <- true
	})
	//ample time for server to be ready to receive requests
	time.Sleep(3 * time.Second)

	t.Log("(1) checking random path returns not found")
	resp, err := http.Post(fmt.Sprintf("http://0.0.0.0:%d", port), "Content-Type: application/json", nil)
	if err != nil {
		t.Fatalf("(1) unexpected error on not found request: %s", err.Error())
	} else if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("(1) received %d instead of %d", resp.StatusCode, http.StatusNotFound)
	}

	t.Log("(2) port scan request one")
	//http://scanme.nmap.org/ and google dns anycast
	req := types.ScanRequest{
		ScanIPs:  []string{"45.33.32.156", "8.8.8.8"},
		ScanPort: 80,
	}
	resp, err = http.Post(fmt.Sprintf("http://0.0.0.0:%d/submit", port), "Content-Type: application/json", MarshalRequest(req))
	idOne := getID(t, 2, err, resp)
	t.Logf("got id %v for scan one", idOne)

	t.Log("(3) port scan request two")
	//9929 is open by nmap for testing
	req = types.ScanRequest{
		ScanIPs:  []string{"45.33.32.156"},
		ScanPort: 9929,
	}
	resp, err = http.Post(fmt.Sprintf("http://0.0.0.0:%d/submit", port), "Content-Type: application/json", MarshalRequest(req))
	idTwo := getID(t, 3, err, resp)
	t.Logf("got id %v for scan two", idTwo)

	//ample time for requests to be processed
	time.Sleep(10 * time.Second)

	t.Log("(4) query port scan request one")
	qReq := types.QueryRequest{
		ScanID: idOne,
	}
	resp, err = http.Post(fmt.Sprintf("http://0.0.0.0:%d/query", port), "Content-Type: application/json", MarshalRequest(qReq))
	queryResp := getQueryResp(t, 4, err, resp)
	assert.Equal(t, uint(80), queryResp.ScanPort)
	assert.True(t, queryResp.Ready)
	google := findStatus("8.8.8.8", queryResp.Status)
	assert.NotNil(t, google)
	assert.Equal(t, types.CLOSED, google.State)
	nmap := findStatus("45.33.32.156", queryResp.Status)
	assert.NotNil(t, nmap)
	assert.Equal(t, types.OPEN, nmap.State)

	t.Log("(5) query port scan request two")
	qReq = types.QueryRequest{
		ScanID: idTwo,
	}
	resp, err = http.Post(fmt.Sprintf("http://0.0.0.0:%d/query", port), "Content-Type: application/json", MarshalRequest(qReq))
	queryResp = getQueryResp(t, 5, err, resp)
	assert.Equal(t, uint(9929), queryResp.ScanPort)
	assert.True(t, queryResp.Ready)
	nmap = findStatus("45.33.32.156", queryResp.Status)
	assert.NotNil(t, nmap)
	assert.Equal(t, types.OPEN, nmap.State)

	t.Log("(6) query non-existent job")

	qReq = types.QueryRequest{
		ScanID: 123,
	}
	resp, err = http.Post(fmt.Sprintf("http://0.0.0.0:%d/query", port), "Content-Type: application/json", MarshalRequest(qReq))
	if err != nil {
		t.Fatalf("(6) unexpected error on not found request: %s", err.Error())
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("(6) expected to get a not found response for a non-existent scan id")
	}
}

func MarshalRequest(req interface{}) io.Reader {
	if bs, err := json.Marshal(req); err != nil {
		panic(err)
	} else {
		return bytes.NewBuffer(bs)
	}
}

func getID(t *testing.T, testNum int, err error, resp *http.Response) uint64 {
	if err != nil {
		t.Fatalf("(%d) unexpected error on scan request: %s", testNum, err.Error())
	} else if resp.StatusCode != http.StatusOK {
		t.Fatalf("(%d) received %d instead of %d", testNum, resp.StatusCode, http.StatusNotFound)
	}

	if bs, err := ioutil.ReadAll(resp.Body); err != nil {
		panic(err)
	} else {
		var resp types.ScanResponse
		if err := json.Unmarshal(bs, &resp); err != nil {
			panic(err)
		}
		return resp.ScanID
	}
}

func getQueryResp(t *testing.T, testNum int, err error, resp *http.Response) types.QueryResponse {
	if err != nil {
		t.Fatalf("(%d) unexpected error on scan request: %s", testNum, err.Error())
	} else if resp.StatusCode != http.StatusOK {
		t.Fatalf("(%d) received %d instead of %d", testNum, resp.StatusCode, http.StatusNotFound)
	}

	if bs, err := ioutil.ReadAll(resp.Body); err != nil {
		panic(err)
	} else {
		var resp types.QueryResponse
		if err := json.Unmarshal(bs, &resp); err != nil {
			panic(err)
		}
		return resp
	}
}

func findStatus(ip string, statuses []types.IPStatus) *types.IPStatus {
	for _, status := range statuses {
		if status.IP == ip {
			return &status
		}
	}
	return nil
}
