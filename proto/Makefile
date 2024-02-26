.PHONY: generate clean

# To avoid use of Git submodules, Hermes and Proto must be placed at the same
# filesystem depth
generate:
	cp -Rf ../../proto/protobuf/api protobuf/
	docker compose build --progress=plain --no-cache --pull
	docker compose up
	docker compose down
	rm -rf protobuf/api
	cp -f ../../proto/openapi/hermes.swagger.json ../web/

clean:
	find . -name '*.pb*.go' -type f|xargs rm -v
