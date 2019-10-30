# project_colfax

##Pre-Reqs
Pre-Reqs are checked in the script and will prompt for install if not met. The list is below.
- git
- jq
- docker
- docker-compose
- vault cli
- fly cli

## To run bootstrap
sh -c "$(curl -fsSL https://raw.githubusercontent.com/EMC-Underground/project_colfax/dev/bootstrap.sh)"

## To destroy bootstrap environment
sh -c "$(curl -fsSL https://raw.githubusercontent.com/EMC-Underground/project_colfax/dev/bootstrap.sh)" destroy
