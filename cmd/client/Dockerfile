FROM golang:1.14 as build

COPY . /go/portscan

WORKDIR /go/portscan

RUN go build -v -o /tmp/pscli cmd/client/pscli.go &&\
    chmod +x /tmp/pscli

FROM gcr.io/distroless/base-debian10

COPY --from=build /tmp/pscli /opt/pscli

ENTRYPOINT ["/opt/pscli"]