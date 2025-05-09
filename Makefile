.PHONY: install lint init_db test unit_test integration_test mod generate

# Non-cgo DNS is more reliable and faster for non-esoteric uses of resolv.conf
export CGO_ENABLED = 0
RFLAG = -buildmode=pie

# Race detector is exclusive of non-cgo and PIE
# https://github.com/golang/go/issues/6508
ifneq ($(RACE),)
export CGO_ENABLED = 1
RFLAG = -race
export GORACE = halt_on_error=1
endif

ifeq ($(strip $(TEST_REDIS_HOST)),)
TEST_REDIS_HOST = 127.0.0.1
endif

ifeq ($(strip $(TEST_PG_URI)),)
TEST_PG_URI = pgx://postgres:postgres@127.0.0.1/hermes_test
endif

install:
	for x in $(shell find cmd -mindepth 1 -type d); do go install $(RFLAG) \
	-ldflags="-w" ./$${x}; done

	for x in $(shell find tool -mindepth 1 -type d); do go install \
	-ldflags="-w" ./$${x}; done

lint:
	go install honnef.co/go/tools/cmd/staticcheck@latest
# staticcheck defaults are all,-ST1000,-ST1003,-ST1016,-ST1020,-ST1021,-ST1022
	staticcheck -checks all ./...

	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	golangci-lint run -E bidichk,copyloopvar,durationcheck,err113,errname \
	-E forcetypeassert,funcorder,godot,gosec,intrange,nlreturn,perfsprint \
	-E prealloc,protogetter,testifylint,unconvert,unparam,usestdlibvars \
	-E usetesting

	go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck -test ./...

init_db:
	echo FLUSHALL|nc -w 2 $(TEST_REDIS_HOST) 6379

	go install -tags pgx github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	migrate -path /tmp -database $(TEST_PG_URI) drop -f
	migrate -path config/db/hermes -database $(TEST_PG_URI) up

test: install lint unit_test integration_test
# -count=1 is the idiomatic way to disable test caching in package list mode
unit_test:
	go test -count=1 -cpu=1,4 -failfast -shuffle=on $(RFLAG) -tags unit ./...
integration_test: init_db
	go test -count=1 -cpu=1,4 -failfast -shuffle=on $(RFLAG) -tags integration \
	./...

mod:
	go get -t -u ./... || true
	go mod tidy -v
	go mod vendor
# Update hermes.swagger.json at the same time as github.com/ownmfa/proto
	if [ -f ../proto/openapi/hermes.swagger.json ]; then cp -f -v \
	../proto/openapi/hermes.swagger.json web/; fi

generate:
	go install go.uber.org/mock/mockgen@latest
	go generate -x ./...
