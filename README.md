# project_colfax

## Pre-Reqs
Pre-Reqs are checked in the script and will prompt for install if not met. The list is below.
- git
- jq
- docker
- docker-compose
- vault cli
- fly cli

## To deploy
sh -c "$(curl -fsSL https://raw.githubusercontent.com/EMC-Underground/project_colfax/dev/bootstrap.sh)"

## To destroy bootstrap environment
sh -c "$(curl -fsSL https://raw.githubusercontent.com/EMC-Underground/project_colfax/dev/bootstrap.sh)" destroy

## About
This project is designed to allow teams to quickly stand up an automation
platform. By default the platform will deploy the following technologies.

- CI/CD | [concourse](https://concourse-ci.org/)
- Container Orchestration | [docker swarm](https://docs.docker.com/engine/swarm/)
- Reverse Proxy | [traefik](https://traefik.io/)
- Functions | [openfaas](https://www.openfaas.com/)
- Dashboard | [grafana](https://grafana.com/)
- Time Series Database | [influxdb](https://www.influxdata.com/)
- Storage API
- Collector Engine [overlord](https://github.com/nctiggy/collector-overlord)
