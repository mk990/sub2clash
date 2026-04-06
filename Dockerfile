# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o app .

# Runtime stage
FROM alpine:latest

WORKDIR /root/

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/app .

EXPOSE 8080

ENTRYPOINT ["./app", "--serv"]
