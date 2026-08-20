FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY main.go ./
COPY internal ./internal
COPY cmd ./cmd
RUN go mod download
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /secret-drop .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /secret-decrypt ./cmd/decrypt

FROM scratch AS app
COPY --from=build /secret-drop /secret-drop
EXPOSE 8080
ENTRYPOINT ["/secret-drop"]

FROM scratch AS decrypt
COPY --from=build /secret-decrypt /secret-decrypt
ENTRYPOINT ["/secret-decrypt"]
