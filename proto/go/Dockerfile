FROM golang:1-alpine

ARG PROTOC_VERSION=36.1

RUN apk update && apk upgrade
RUN apk add --no-cache make git curl unzip
RUN curl -L -o /tmp/protoc.zip \
https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-aarch_64.zip
RUN unzip /tmp/protoc.zip -d /usr

WORKDIR /proto
