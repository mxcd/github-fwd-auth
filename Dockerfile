FROM golang:1.25 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /usr/src

COPY go.mod go.sum ./
COPY pkg/githuboauth/go.mod pkg/githuboauth/go.sum ./pkg/githuboauth/
RUN go mod download

# Copy the go source
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o server ./cmd/server/main.go

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /usr/src/server .
USER 65532:65532

ENTRYPOINT ["/server"]
