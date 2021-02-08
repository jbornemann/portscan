PortScan

### Prerequisites

If building with docker, a recent release of Docker installed with multi-stage build support. If compiling Go directly, have Go 1.14 or later installed. 

### Building

Builds (docker and go directly) must be completed from the project root directory

###### Client

To build pscli (the client), run 

`
go build cmd/client/pscli.go
`

or

`
docker build . -f cmd/client/Dockerfile
`

###### Server

To build pscan (the server), run

`
go build cmd/server/pscan.go
`

or

`
docker build . -f cmd/server/Dockerfile
`

### Running Tests

To run unit tests, from the root directory run

`
go test ./...
`

To run integration tests, from the root directory run

`
go test -tags=integration ./...
`

### Use

Run the server with 

`
./pscan --port 8080
`

Submit a scan request

`
./pscli --host localhost:8080 submit --ips 8.8.8.8,172.217.5.238 --port 443
`

You should get an ID from the above command to use to query for results, plug this into the query command like so:

`
./pscli --host localhost:8080 query --id 5577006791947779410
`