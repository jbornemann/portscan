package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/jbornemann/portscan/pkg/types"
)

const (
	defaultScheme = "http"
)

//CommandLineArgs represent direct, unmodified arguments received by the CLI
type CommandLineArgs struct {
	Host string

	ScanIPs  []string
	ScanPort string

	ScanID string
}

//SubmitRequest represents all of the information the CLI needs to execute a port scan request
type SubmitRequest struct {
	Host url.URL
	types.ScanRequest
}

//Query represents the information needed to query an existing scan
type Query struct {
	Host url.URL
	types.QueryRequest
}

//PrepareSubmitRequest will ensure that the CommandLineArgs received are well-formed, and valid for this request.
//If so it will return a SubmitRequest
//If the arguments can not be validated, an error will returned, along with a nil SubmitRequest
func (c CommandLineArgs) PrepareSubmitRequest() (*SubmitRequest, error) {
	request := &SubmitRequest{}

	if host, err := parseHostString(c.Host); err != nil {
		return nil, err
	} else {
		host.Path = "/submit"
		request.Host = *host
	}

	if c.ScanIPs == nil {
		return nil, fmt.Errorf("you must provide a list of ips to scan")
	}

	if len(c.ScanPort) == 0 {
		return nil, fmt.Errorf("you must provide a port to scan")
	} else if port, err := strconv.ParseUint(c.ScanPort, 10, 32); err != nil {
		return nil, fmt.Errorf("%s is not a valid port to scan", c.ScanPort)
	} else {
		scanRequest := types.ScanRequest{
			ScanIPs:  c.ScanIPs,
			ScanPort: uint(port),
		}
		if valid, err := scanRequest.Validate(); !valid {
			return nil, err
		} else {
			request.ScanRequest = scanRequest
		}
	}

	return request, nil
}

//PrepareQuery will transform command line arguments into a Query, given that the correct arguments were set and that they are valid
//If arguments are not valid for this request, an error will be returned with a nil Query
func (c CommandLineArgs) PrepareQuery() (*Query, error) {
	query := &Query{}

	if host, err := parseHostString(c.Host); err != nil {
		return nil, err
	} else {
		host.Path = "/query"
		query.Host = *host
	}

	if len(c.ScanID) == 0 {
		return nil, fmt.Errorf("you must provide an scan id to query")
	} else if id, err := strconv.ParseUint(c.ScanID, 10, 64); err != nil {
		return nil, fmt.Errorf("not a valid scan id")
	} else {
		query.ScanID = id
	}

	return query, nil
}

//Submit will process a CLI submit request, with the given Client
//the client passed may not be nil
func Submit(r SubmitRequest, client *http.Client) error {
	scanReq := r.ScanRequest

	var resp types.ScanResponse
	if err, statusCode := doPost(client, r.Host.String(), "application/json", scanReq, &resp); err != nil {
		return err
	} else {
		if statusCode != http.StatusOK {
			fmt.Printf("problem submitting scan\n")
		} else {
			fmt.Printf("use %d to query scan results\n", resp.ScanID)
		}
	}

	return nil
}

//DoQuery will process a CLI query request, with the given Client
//the client passed may not be nil
func DoQuery(q Query, client *http.Client) error {
	req := q.QueryRequest

	var resp types.QueryResponse
	if err, statusCode := doPost(client, q.Host.String(), "application/json", req, &resp); err != nil {
		return err
	} else {
		if statusCode == http.StatusNotFound {
			fmt.Printf("scan id %v is not a known id\n", req.ScanID)
		} else if !resp.Ready {
			fmt.Printf("scan %v is not yet ready\n", q.ScanID)
		} else {
			fmt.Printf("results of scan of port %d\n", resp.ScanPort)
			for _, status := range resp.Status {
				fmt.Printf("ip %s in state %s\n", status.IP, status.State)
			}
		}
	}

	return nil
}

func doPost(client *http.Client, endpoint, contentType string, in interface{}, out interface{}) (error, int) {
	bs, err := json.Marshal(&in)
	if err != nil {
		return fmt.Errorf("bug! could not marshal request, error was: %s", err.Error()), -1
	}
	buf := bytes.NewBuffer(bs)
	if resp, err := client.Post(endpoint, contentType, buf); err != nil {
		return fmt.Errorf("could not make call to pscan server, error was: %s", err.Error()), -1
	} else {
		bs, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("could not read body from pscan server, error was: %s", err.Error()), resp.StatusCode
		}
		if resp.StatusCode != http.StatusOK {
			return nil, resp.StatusCode
		}

		if err := json.Unmarshal(bs, &out); err != nil {
			return fmt.Errorf("unexpected response body from pscan server, error was: %s", err.Error()), resp.StatusCode
		}
	}
	return nil, http.StatusOK
}

func parseHostString(hostString string) (*url.URL, error) {
	if len(hostString) == 0 {
		return nil, fmt.Errorf("you must provide a pscan server host")
	}

	if !strings.HasPrefix(hostString, "https://") || strings.HasPrefix(hostString, "http://") {
		hostString = fmt.Sprintf("%s://%s", defaultScheme, hostString)
	}

	if !govalidator.IsURL(hostString) {
		return nil, fmt.Errorf("pscan server host is not valid")
	} else if host, err := url.Parse(hostString); err != nil {
		return nil, fmt.Errorf("could not parse host: %s", err.Error())
	} else {
		return host, nil
	}
}
