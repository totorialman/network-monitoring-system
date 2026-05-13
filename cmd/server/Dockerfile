FROM golang:1.21-alpine AS builder

WORKDIR /src
RUN apk add --no-cache ca-certificates git

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/network-monitor ./cmd/server

FROM alpine:3.19

RUN apk add --no-cache ca-certificates wget tzdata
WORKDIR /app
COPY --from=builder /out/network-monitor /app/network-monitor

EXPOSE 8080
ENTRYPOINT ["/app/network-monitor"]
