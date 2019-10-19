#!/bin/bash

# Set Color Variables
red=`tput setaf 1`
green=`tput setaf 2`
cyan=`tput setaf 6`
reset=`tput sgr0`
check="\xE2\x9C\x94"
cross="\xE2\x9C\x98"
min_dv="18.09"
min_dcv="1.24"

function version { echo "$@" | gawk -F. '{ printf("%03d%03d%03d\n", $1,$2,$3); }'; }

print_check() {
    printf "${green}${check}\n"
}

print_cross() {
    printf "${red}${cross}\n"
    exit 1
}

success() {
    if [ $? -eq 0 ]
    then
        print_check
    else
        print_cross
    fi
}

docker_checks() {
    printf "${cyan}Checking For Docker.... "
    which docker > /dev/null 2>&1

    if [ $? -eq 0 ]
    then
        print_check
        printf "${cyan}Checking Version 18.09.0 or greater.... "
        dv=`docker --version | awk -F'[, ]' '{print $3}'`
        if [ "$(version ${dv})" -ge "$(version ${min_dv})" ]
        then
            print_check
        else
            print_cross
        fi
    else
        print_cross
    fi
}

docker_compose_checks() {
    printf "${cyan}Checking for docker-compose.... "
    which docker-compose > /dev/null 2>&1

    if [ $? -eq 0 ]
    then
        print_check
        printf "${cyan}Checking Version 1.24.0 or greater.... "
        dcv=`docker-compose version | awk -F'[, ]' 'NR==1 {print $3}'`
        if [ "$(version ${dcv})" -ge "$(version ${min_dcv})" ]
        then
            print_check
        else
            print_cross
        fi
    else
        print_cross
    fi
}

pull_concourse_repo() {
    printf "${cyan}Cloning Concourse Repo.... "
    if [ ! -d "./concourse-docker" ]
    then
        git clone https://github.com/EMC-Underground/concourse-docker.git > /dev/null 2>&1
        success
        cd ./concourse-docker
    else
        cd ./concourse-docker
        git pull > /dev/null 2>&1
        success
    fi
}

pull_vault_repo() {
    printf "${cyan}Cloning Vault Repo.... "
    if [ ! -d "./vault-consul-docker" ]
    then
        git clone https://github.com/EMC-Underground/vault-consul-docker.git > /dev/null 2>&1
        success
        cd ./vault-consul-docker
    else
        cd ./vault-consul-docker
        git pull > /dev/null 2>&1
        success
    fi
}

generate_keys() {
    printf "${cyan}Generating Concourse Keys.... "
    bash ./keys/generate > /dev/null 2>&1
    success
}

deploy_concourse() {
    printf "${cyan}Deploying Concourse.... "
    docker-compose up -d > /dev/null 2>&1
    success
    cd ../
}

build_deploy_vault() {
    printf "${cyan}Deploying Vault.... "
    docker-compose up -d --build > /dev/null 2>&1
    success
    cd ../
}

cleanup() {
    cd vault-consul-docker
    docker-compose kill
    cd ../concourse-docker
    docker-compose kill
    cd ..
    sudo rm -Rf vault-consul-docker
    sudo rm -Rf concourse-docker
    rm concourse-policy.hcl
    docker system prune -f
}

vault_init() {
    printf "${cyan}Initializing Vault.... "
    sleep 5
    local  __resultvar=$1
    local result=`vault operator init -address=http://localhost:8200 -key-threshold=1 -key-shares=1 -format=json`
    success
    eval $__resultvar="'$result'"
}

vault_unseal() {
    printf "${cyan}Unsealing the vault.... "
    vault operator unseal -address=http://localhost:8200 $1 > /dev/null 2>&1
    success
}

vault_create_store() {
    printf "${cyan}Creating vault secret store.... "
    vault secrets enable -address=http://localhost:8200 -version=1 -path=concourse kv > /dev/null 2>&1
    success
}

vault_create_team_store() {
    printf "${cyan}Creating vault openfaas secret store.... "
    vault secrets enable -address=http://localhost:8200 -version=1 -path=concourse/openfaas kv > /dev/null 2>&1
    success
}

vault_create_policy() {
    printf "${cyan}Create vault policy.... "
    echo 'path "concourse/*" {
  policy = "read"
}' >> concourse-policy.hcl
    vault policy write -address=http://localhost:8200 concourse ./concourse-policy.hcl > /dev/null 2>&1
    success
}

vault_create_token() {
    printf "${cyan}Create vault service account.... "
    local __resultvar=$1
    local result=`vault token create -address=http://localhost:8200 -display-name=concourse -format=json --policy concourse --period 1h| jq -r .auth.client_token`
    success
    eval $__resultvar="'$result'"
}

vault_login() {
    printf "${cyan}Logging into vault.... "
    vault login -address=http://localhost:8200 $1 > /dev/null 2>&1
    success
}

build_docker_network() {
    printf "${cyan}Building docker bridge network.... "
    docker network create comms > /dev/null 2>&1
    success
}

if [[ $# -eq 0 ]]
then
    docker_checks
    docker_compose_checks
    build_docker_network
    pull_vault_repo
    build_deploy_vault
    vault_init keys
    unseal=`echo $keys | jq -r .unseal_keys_b64[0]`
    roottoken=`echo $keys | jq -r .root_token`
    vault_unseal $unseal
    vault_login $roottoken
    vault_create_store
    #vault_create_team_store
    vault_create_policy
    vault_create_token token
    pull_concourse_repo
    generate_keys
    export VAULT_CLIENT_TOKEN=$token
    deploy_concourse
    echo "${cyan}Vault Concourse Key: ${green}${token}"
    echo "${cyan}Vault Root Key: ${green}${roottoken}"
fi

case "$1" in
    "destroy") cleanup
esac
