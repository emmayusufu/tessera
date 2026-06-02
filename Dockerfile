FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/emmayusufu/tessera/internal/version.Version=${VERSION}" \
    -o /out/coordinator ./cmd/coordinator
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/emmayusufu/tessera/internal/version.Version=${VERSION}" \
    -o /out/agent ./cmd/agent
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/emmayusufu/tessera/internal/version.Version=${VERSION}" \
    -o /out/tessera ./cmd/tessera

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/coordinator /usr/local/bin/coordinator
COPY --from=build /out/agent       /usr/local/bin/agent
COPY --from=build /out/tessera     /usr/local/bin/tessera
USER nonroot:nonroot
WORKDIR /var/lib/tessera
ENTRYPOINT ["/usr/local/bin/coordinator"]
