FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /hallpass ./cmd/hallpass

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /hallpass /hallpass
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/hallpass"]
CMD ["serve", "-config", "/etc/hallpass/hallpass.yaml"]
