# nsq

GitHub Actions
[do not support](https://github.community/t/how-do-i-properly-override-a-service-entrypoint/17435)
overriding a Docker `CMD` or `ENTRYPOINT` for services. These images wrap the
production NSQ images and set specific `CMD` values for each service.

## Build

```
docker login -u ownmfa

docker build -f Dockerfile-nsqlookupd -t ownmfa/nsqlookupd:v1.2.0 .
docker push ownmfa/nsqlookupd:v1.2.0

docker build -f Dockerfile-nsqd -t ownmfa/nsqd:v1.2.0 .
docker push ownmfa/nsqd:v1.2.0

docker build -f Dockerfile-nsqadmin -t ownmfa/nsqadmin:v1.2.0 .
docker push ownmfa/nsqadmin:v1.2.0

docker logout
```

## Usage

```
docker run -it --env LOG_LEVEL=info ownmfa/nsqlookupd:v1.2.0

docker run -it --env LOOKUP_ADDR=nsqlookupd:4160 --env LOG_LEVEL=info ownmfa/nsqd:v1.2.0

docker run -it --env LOOKUP_ADDR=nsqlookupd:4161 --env LOG_LEVEL=info ownmfa/nsqadmin:v1.2.0
```
