# Manual build:
# DOCKER=y GOOS=linux make
# docker login -u ownmfa -p XXX ghcr.io
# TAG=$(git rev-parse --short=8 HEAD)
# docker build -f build/Dockerfile -t ghcr.io/ownmfa/hermes:${TAG} .
# docker push ghcr.io/ownmfa/hermes:${TAG}
# docker logout ghcr.io
FROM alpine

# Add CA certificates and timezone info
RUN apk update && apk upgrade
RUN apk add --no-cache ca-certificates tzdata

# Add build files
COPY bin/* /bin/
COPY web/* /web/

USER nobody
