# tpp-onboarding-application
Downloadable tool which allows creation of an SSA and onboarding with ASPSPs

## Prerequisites

Docker containers wrap up a piece of software in a complete filesystem that contains everything 
it needs to run: code, runtime, system tools, system libraries etc.
This guarantees that it will always run the same, regardless of the environment it is running in. 
https://www.docker.com/what-docker

All of the commands for interacting with the project should be issued within
the `docker-compose` environment.

## Installation

To clone the repository, issue the following command:

```bash
git clone https://github.com/OpenBankingUK/tpp-onboarding-application
```

To build for testing in a local environment, change to the directory that you
cloned the repository to and issue the following `docker-compose` command:

```bash
docker-compose -f local.yml build
```

This will fetch the all of the dependencies for the project.

## Usage

All of the commands for interacting with the project should be issued within
the `docker-compose` environment.

To start a local instance of the server, issue the following command:

```bash
docker-compose -f local.yml up
```

The server will be available at [http://localhost](http://localhost/).

## Environment Variables

This section documents the environment variables that can be used to configure
an instance.

|Variable                 |Default                      |
|-------------------------|-----------------------------|
|`CACHE_TIMEOUT`          |3600                         |
|`TEMPLATES_FOLDER `      |"templates "                 |                     
|`TEST_API_ENDPOINT`      |"/accounts"                  |
|`FLASK_DEBUG      `      |True                         |
|`SECRET_KEY`             | hex(16)                     |

## Copyright

See COPYRIGHT.
