FROM golang:1.23-alpine

RUN apk update && apk upgrade
RUN apk add --no-cache make protobuf protobuf-dev git

WORKDIR /api
