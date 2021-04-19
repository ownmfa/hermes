.PHONY: generate clean

# To avoid use of Git submodules, Hermes and API must be placed at the same
# filesystem depth
generate:
	cp -Rf ../../api/protobuf/common protobuf/
	docker compose build --no-cache --pull
	docker compose up --remove-orphans
	rm -rf protobuf/common
	cp -f ../../api/openapi/hermes.swagger.json ../web/

clean:
	find . -name '*.pb*.go' -type f|xargs rm -v
