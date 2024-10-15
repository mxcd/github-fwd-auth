FROM golang:1.23 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /usr/src

COPY go.mod /usr/src/go.mod
COPY go.sum /usr/src/go.sum

RUN go mod download

# Copy the go source
COPY cmd /usr/src/cmd
COPY internal /usr/src/internal
COPY pkg /usr/src/pkg

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o server /usr/src/cmd/server/main.go

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /usr/src/server .
USER 65532:65532

ENTRYPOINT ["/server"]
