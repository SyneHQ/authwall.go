FROM --platform=$BUILDPLATFORM golang:1.26.8-alpine AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags '-w -s' -o authwall .

FROM gcr.io/distroless/cc-debian12 AS runner

COPY --from=builder /app/authwall /usr/local/bin/authwall

ENTRYPOINT ["authwall"]