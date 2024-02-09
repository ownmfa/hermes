# Manual build:
# docker login -u ownmfa -p XXX ghcr.io
# TAG=$(git rev-parse --short=8 HEAD)
# docker buildx create --use
## docker buildx build -f build/Dockerfile -t ghcr.io/ownmfa/hermes:${TAG} --platform linux/amd64,linux/arm64 --push .
# docker buildx build -f build/Dockerfile -t ghcr.io/ownmfa/hermes:${TAG} --push .
# docker buildx rm
# docker logout ghcr.io
FROM golang:1.22-alpine AS build

# Add packages needed to support builds and tests
RUN apk update && apk upgrade
RUN apk add --no-cache make
RUN go env

COPY . /opt/hermes/
RUN mkdir -p /opt/hermes/bin
WORKDIR /opt/hermes/

RUN GOBIN=/opt/hermes/bin make install

FROM alpine

# Add CA certificates and timezone info
RUN apk update && apk upgrade
RUN apk add --no-cache ca-certificates tzdata

# Add build files
COPY --from=build /opt/hermes/bin/* /bin/
COPY web/* /web/

USER nobody
