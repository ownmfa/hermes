# Hermes

### OwnMFA MFA platform

## Getting Started

Install any compliant package of [Docker](https://docs.docker.com/get-started/overview/), [Docker Compose](https://docs.docker.com/compose/), and [Go](https://go.dev/dl/). Consider using [Colima](https://github.com/abiosoft/colima):

```
brew install colima docker docker-compose docker-buildx
colima start --cpu 3 --memory 3 --disk 16 --mount-type virtiofs --mount ~/code/go:w --vz-rosetta
```

Run the build and tests:

```
docker compose -f build/docker-compose.yml up -d
make test
RACE=y make test
docker compose -f build/docker-compose.yml down
```

## Running an API Locally

First complete the above steps, leaving dependency containers running. Then:

```
hermes-create org testorg testadmin@ownmfa.com testpass
API_PWT_KEY=$(dd if=/dev/random bs=1 count=32|base64) API_IDENTITY_KEY=${API_PWT_KEY} API_API_HOST=127.0.0.1 hermes-api

curl -v -X POST -d '{"email":"testadmin@ownmfa.com", "orgName":"testorg", "password":"testpass"}' http://localhost:8000/v1/sessions/login
```

OpenAPI live docs are available at [http://localhost:8000/](http://localhost:8000/).

## Tutorial

Getting started with the Hermes API:

- Log in with `/v1/sessions/login` using your provided credentials. Click `Authorize` below and enter the returned token.
- Create an application with `/v1/applications`. For SMS and software token authentication methods, all template fields can be left empty.
- (Optional) Create an `AUTHENTICATOR` role API key with `/v1/sessions/keys`. Re-authorize using the returned token.

Activate an identity (single occurrence):

- Create an identity with `/v1/applications/{identity.appID}/identities`. Only one method field is supported when creating an identity.
- Issue the returned identity a challenge with `/v1/applications/{appID}/identities/{id}/challenge`.
- Activate the identity with `/v1/applications/{appID}/identities/{id}/activate` using the received or generated challenge.

Verify an identity (ongoing):

- Issue the identity a challenge with `/v1/applications/{appID}/identities/{id}/challenge`.
- Verify the identity with `/v1/applications/{appID}/identities/{id}/verify` using the received or generated challenge.

## Deploying

[Docker Compose](https://docs.docker.com/compose/) files for the Hermes platform and its dependencies are available in `build/deploy/`. These can be used for a single-system deploy, or as templates for orchestration tooling such as [Nomad](https://www.nomadproject.io/) or [Kubernetes](https://kubernetes.io/). Keys should be provided where applicable.

## Use of Build Tags In Tests

All non-generated test files should have build tags, including `main_test.go`. Due to limitations of developer tools and extensions, negated tags are used.

For example, to tag a file as a unit test:

```
// +build !integration
```

To tag a file as an integration test:

```
// +build !unit
```

To find test files that are missing build tags, the following command can be run:

```
find . -name '*_test.go' -type f|grep -v /mock_|xargs grep -L '//go:build'
```
