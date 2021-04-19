.PHONY: generate deps token

generate: deps token

deps:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

token:
	protoc -I=../protobuf --go_out=. --go_opt=paths=source_relative \
	token/web.proto \
	token/page.proto
