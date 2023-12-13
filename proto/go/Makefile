.PHONY: generate deps message token

generate: deps message token

deps:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

message:
	protoc -I=../protobuf --go_out=. --go_opt=paths=source_relative \
	message/ownmfa_notifier_in.proto

token:
	protoc -I=../protobuf --go_out=. --go_opt=paths=source_relative \
	token/ownmfa_web.proto \
	token/ownmfa_page.proto
