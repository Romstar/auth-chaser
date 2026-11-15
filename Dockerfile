# Build a static Linux binary for self-hosted and CLI use.
FROM golang:1.23-alpine AS build
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=0.1.0
ARG COMMIT=docker
RUN CGO_ENABLED=0 GOOS=linux go build \
  -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
  -o /out/auth-chaser ./cmd/auth-chaser

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata \
  && adduser -D -H -u 10001 chaser
USER chaser
COPY --from=build /out/auth-chaser /usr/local/bin/auth-chaser
EXPOSE 8080
ENTRYPOINT ["auth-chaser"]
CMD ["serve", "--addr", ":8080"]
