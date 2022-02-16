.PHONY: generate clean

# To avoid use of Git submodules, Hermes and API must be placed at the same
# filesystem depth
generate:
	cp -Rf ../../api/protobuf/api protobuf/
	docker compose build --no-cache --pull
	docker compose up
	docker compose down
	rm -rf protobuf/api
	cp -f ../../api/openapi/hermes.swagger.json ../web/

clean:
	find . -name '*.pb*.go' -type f|xargs rm -v
