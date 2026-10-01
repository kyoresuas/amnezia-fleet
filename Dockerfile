FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/fleetd ./cmd/fleetd \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/fleet-probe ./cmd/fleet-probe

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata && adduser -D -H -u 10001 fleet
COPY --from=build /out/fleetd /out/fleet-probe /usr/local/bin/
USER fleet
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/fleetd"]
