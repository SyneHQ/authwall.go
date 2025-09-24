FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-w -s' -o authwall main.go

FROM gcr.io/distroless/cc-debian12 AS runner

COPY --from=builder /app/authwall /usr/local/bin/authwall

ENTRYPOINT ["authwall"]