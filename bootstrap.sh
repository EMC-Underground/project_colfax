#!/bin/bash

# Set Color Variables
red=`tput setaf 1`
green=`tput setaf 2`
cyan=`tput setaf 6`
magenta=`tput setaf 5`
reset=`tput sgr0`
check="\xE2\x9C\x94"
cross="\xE2\x9C\x98"
min_dv="18.09"
min_dcv="1.24"
min_vv="1.2.4"
min_fv="5.5.1"

function version { echo "$@" | gawk -F. '{ printf("%03d%03d%03d\n", $1,$2,$3); }'; }

print_check() {
    printf "${green}${check}\n"
}

print_version() {
    case $2 in
        good)
            printf "${green}${1}\n"
            ;;
        bad)
            printf "${red}${1}"
            exit 1
            ;;
    esac
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

success_version() {
    if [ "$(version ${1})" -ge "$(version ${2})" ]
    then
        print_version $1 "good"
    else
        print_version $1 "bad"
    fi
}

docker_checks() {
    printf "${cyan}Checking docker version.... "
    dv=`docker --version | awk -F'[, ]' '{print $3}'`
    if [ $? -eq 0 ]
    then
        success_version $dv $min_dv
    else
        print_cross
    fi
}

docker_compose_checks() {
    printf "${cyan}Checking docker-compose version.... "
    dcv=`docker-compose version | awk -F'[, ]' 'NR==1 {print $3}'`
    if [ $? -eq 0 ]
    then
        success_version $dcv $min_dcv
    else
        print_cross
    fi
}

vault_checks() {
    printf "${cyan}Checking vault cli version.... "
    vv=`vault -v | awk '{print substr($2,2)}'`
    if [ $? -eq 0 ]
    then
        success_version $vv $min_vv
    else
        print_cross
    fi
}

fly_checks() {
    printf "${cyan}Checking for fly cli version.... "
    fv=`fly --version`
    if [ $? -eq 0 ]
    then
        success_version $fv $min_fv
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

how_many_servers() {
    printf "${magenta}How many servers will you use: ${reset}"
    local __resultvar=$1
    read result
    eval $__resultvar="'$result'"
}

capture_server_ips() {
    printf "${magenta}Enter server IP addresses\n"
    for ((i=0; i<$1; i++))
    do
        printf "${cyan}Server[${i}]: ${reset}"
        read ip$i
    done
}


if [[ $# -eq 0 ]]
then
    docker_checks
    docker_compose_checks
    fly_checks
    vault_checks
    how_many_servers num_servers
    capture_server_ips $num_servers
    build_docker_network
    pull_vault_repo
    build_deploy_vault
    vault_init keys
    unseal=`echo $keys | jq -r .unseal_keys_b64[0]`
    roottoken=`echo $keys | jq -r .root_token`
    vault_unseal $unseal
    vault_login $roottoken
    vault_create_store
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
