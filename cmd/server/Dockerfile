FROM golang:1.14 as build

COPY . /go/portscan

WORKDIR /go/portscan

RUN go build -v -o /tmp/pscan cmd/server/pscan.go &&\
    chmod +x /tmp/pscan

FROM gcr.io/distroless/base-debian10

COPY --from=build /tmp/pscan /opt/pscan

ENTRYPOINT ["/opt/pscan", "--port", "8080"]

EXPOSE 8080