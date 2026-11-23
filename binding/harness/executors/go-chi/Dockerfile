FROM golang:1.27.4-alpine3.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/bench .

FROM alpine:3.24
ENV FRAMEWORK_TAG=go-chi OVERRIDE=off VERIFY_MODE=off
COPY --from=build /out/bench /usr/local/bin/bench
RUN mkdir -p /logs
EXPOSE 8080
CMD ["/usr/local/bin/bench"]

# W15 ext-routes: ROUTES=v2 enables the richer v1 route space (build :v2 with --build-arg ROUTES=v2).
ARG ROUTES=off
ENV ROUTES=${ROUTES}
