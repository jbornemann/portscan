package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	pnet "github.com/jbornemann/portscan/internal/net"
	"github.com/jbornemann/portscan/pkg/types"
)

//CommandLineArgs represents unmodified, direct arguments to start a port scan server
type CommandLineArgs struct {
	ListenPort string
}

//ValidateAndPrepare for a CommandLineArgs prepares a server configuration if the arguments given are valid
//ValidateAndPrepare will return an error if these CommandLineArgs are not valid
func (c CommandLineArgs) ValidateAndPrepare() (*Configuration, error) {
	if len(c.ListenPort) == 0 {
		return nil, fmt.Errorf("must provide a listen port")
	} else if port, err := strconv.ParseUint(c.ListenPort, 10, 32); err != nil {
		return nil, fmt.Errorf("listen port is not valid")
	} else if !pnet.ValidPort(uint(port)) {
		return nil, fmt.Errorf("listen port is not within valid port range")
	} else {
		return &Configuration{
			ListenPort: uint(port),
		}, nil
	}
}

//Configuration represents the runtime configuration for this port scan server
type Configuration struct {
	ListenPort uint
}

func getState(ip string, port uint) types.State {
	if con, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 5*time.Second); err != nil {
		return types.CLOSED
	} else {
		_ = con.Close()
		return types.OPEN
	}
}

type job struct {
	ScanID uint64
	Port   uint
	IPs    []string
}

type server struct {
	config Configuration

	//Map of ScanID to QueryResponse
	jobs   sync.Map
	workCh chan job
}

//NewServer returns a new server for the provided Configuration
func NewServer(config Configuration) *server {
	return &server{
		config: config,
		jobs:   sync.Map{},
		workCh: make(chan job),
	}
}

//Run starts the server. Send to killCh to shutdown the server.
func (s *server) Run(killCh <-chan bool) {
	mux := http.NewServeMux()
	mux.Handle("/submit", http.HandlerFunc(s.submitRequest))
	mux.Handle("/query", http.HandlerFunc(s.query))
	mux.Handle("*", http.NotFoundHandler())
	server := http.Server{
		Addr:    fmt.Sprintf(":%d", s.config.ListenPort),
		Handler: mux,
	}

	go func() {
		log.Printf("listening on %d\n", s.config.ListenPort)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalln(err.Error())
		}
	}()

	//Begin processing port scan requests received in the background
	go s.processWork()

	<-killCh
	log.Println("shutting down")
	//Give server some time to gracefully respond to active connections
	waitCtx, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	if err := server.Shutdown(waitCtx); err != nil && err != http.ErrServerClosed {
		log.Fatalln(err.Error())
	}
	close(s.workCh)
	log.Println("goodbye")
}

func (s *server) submitRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if bs, err := ioutil.ReadAll(r.Body); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf(err.Error())
		return
	} else {
		var request types.ScanRequest
		if err := json.Unmarshal(bs, &request); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf("bad submit request body (%s)", string(bs))
			return
		}
		log.Printf("got request to scan : %+v", request)
		if valid, err := request.Validate(); !valid {
			log.Printf("request not valid: %+v", request)
			w.WriteHeader(http.StatusBadRequest)
			if err != nil {
				_, _ = w.Write([]byte(err.Error()))
			}
			return
		}
		scanId := rand.Uint64()
		s.workCh <- job{
			ScanID: scanId,
			Port:   request.ScanPort,
			IPs:    request.ScanIPs,
		}
		log.Printf("%v submitted for work", scanId)
		s.jobs.Store(scanId, types.QueryResponse{
			Ready:    false,
			ScanPort: request.ScanPort,
		})
		resp := types.ScanResponse{
			ScanID: scanId,
		}
		bs, err := json.Marshal(&resp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf(err.Error())
			return
		}
		_, _ = w.Write(bs)
	}
}

func (s *server) query(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if bs, err := ioutil.ReadAll(r.Body); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf(err.Error())
		return
	} else {
		var req types.QueryRequest
		if err := json.Unmarshal(bs, &req); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf("bad query request body (%s)", string(bs))
			return
		}
		var resp types.QueryResponse
		if work, found := s.jobs.Load(req.ScanID); found {
			resp = work.(types.QueryResponse)
		} else {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		bs, err := json.Marshal(&resp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf(err.Error())
			return
		}
		_, _ = w.Write(bs)
	}
}

func (s *server) processWork() {
	for job := range s.workCh {
		go s.processJob(job)
	}
}

func (s *server) processJob(job job) {
	wg := &sync.WaitGroup{}
	results := make([]types.IPStatus, len(job.IPs))
	for i, ip := range job.IPs {
		wg.Add(1)
		go func(index int, ip string) {
			state := getState(ip, job.Port)
			results[index] = types.IPStatus{
				IP:    ip,
				State: state,
			}
			wg.Done()
		}(i, ip)
	}
	wg.Wait()
	log.Printf("%v completed", job.ScanID)
	resp := types.QueryResponse{
		Ready:    true,
		ScanPort: job.Port,
		Status:   results,
	}
	s.jobs.Store(job.ScanID, resp)
}
