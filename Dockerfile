FROM golang:1.25-alpine AS build
WORKDIR /src
COPY main.go .
RUN go mod init secret-drop && CGO_ENABLED=0 go build -ldflags="-s -w" -o /secret-drop main.go

FROM scratch
COPY --from=build /secret-drop /secret-drop
EXPOSE 8080
ENTRYPOINT ["/secret-drop"]
