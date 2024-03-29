# nsq

GitHub Actions
[do not support](https://github.community/t/how-do-i-properly-override-a-service-entrypoint/17435)
overriding a Docker `CMD` or `ENTRYPOINT` for services. These images wrap the
production NSQ images and set specific `CMD` values for each service.

## Build

```
docker login -u ownmfa -p XXX ghcr.io
docker buildx create --use

docker buildx build -f Dockerfile-nsqlookupd -t ghcr.io/ownmfa/nsqlookupd:v1.3.0 --platform linux/amd64,linux/arm64 --push .

docker buildx build -f Dockerfile-nsqd -t ghcr.io/ownmfa/nsqd:v1.3.0 --platform linux/amd64,linux/arm64 --push .

docker buildx rm
docker logout ghcr.io
```

## Usage

```
docker run -it ghcr.io/ownmfa/nsqlookupd:v1.3.0

docker run -it --env LOOKUP_ADDR=nsqlookupd:4160 ghcr.io/ownmfa/nsqd:v1.3.0
```
