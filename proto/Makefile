.PHONY: generate clean

# To avoid use of Git submodules, Hermes and Proto must be placed at the same
# filesystem depth
generate:
	cp -Rf ../../proto/protobuf/api protobuf/
	docker compose --progress=plain build --no-cache --pull
	docker compose up --menu=false
	docker compose down
	rm -rf protobuf/api
	cp -f ../../proto/openapi/hermes.swagger.json ../web/

clean:
	find . -name '*.pb*.go' -type f|xargs rm -v
