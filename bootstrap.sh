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
min_vv="1.2.3"
min_fv="5.5.1"
min_jv="1.5"

function version { echo "$@" | gawk -F. '{ printf("%03d%03d%03d\n", $1,$2,$3); }'; }

check_kernel() {
    printf "${cyan}Kernel Version... ${reset}"
    local  __resultvar=$1
    local result=`uname -r | awk -F- '{print $1}'`
    printf "${green}${result}\n"
    local maj_ver=`echo result | cut -d'.' -f1`
    eval $__resultvar="'$maj_ver'"
}

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

jq_checks() {
    printf "${cyan}Checking jq cli version.... "
    jv=`jq --version | awk -F- '{print $NF}'`
    if [ $? -eq 0 ]
    then
        success_version $jv $min_jv
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
    case $kernel_version in
    4)
        export STORAGE_DRIVER=overlay
        ;;
    3)
        export STORAGE_DRIVER=btrfs
        ;;
    *)
        print_cross;;
    esac
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
    sleep 3
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

create_vault_secret() {
    printf "${cyan}Creating ${2} vault secret.... "
    vault kv put -address=http://localhost:8200 $1$2 value=$3 > /dev/null 2>&1
    success
}

build_docker_network() {
    printf "${cyan}Building docker bridge network.... "
    docker network create comms > /dev/null 2>&1
    success
}

capture_num_servers() {
    printf "${magenta}How many servers will you use (odd numbers only): ${reset}"
    local __resultvar=$1
    until [ $((result%2)) -ne 0 ]
    do
        read result
    done
    eval $__resultvar="'$result'"
}

capture_server_ips() {
    printf "${magenta}Enter server IP addresses\n"
    local __resultvar=$1
    local i=0
    local servers=()
    while [[ $i -lt $2 ]]
    do
        printf "${magenta}Server[${i}]: ${reset}"
        read ip$i
        eval p="\$ip${i}"
        valid_ip $p
        if [ $? -ne 0 ]
        then
            echo "${red}Please enter a valid IP Address"
        else
            [[ " ${servers[@]} " =~ " ${p} " ]] && echo "${red}Please enter a unique IP Address"
            [[ ! " ${servers[@]} " =~ " ${p} " ]] && servers[$i]=$p && ((i++)) && continue
        fi
    done
    local result=$(join_by , "${servers[@]}")
    eval $__resultvar="'$result'"
}

capture_username() {
    local result=""
    printf "${magenta}Enter username (root): ${reset}"
    local __resultvar=$1
    read result
    if [ "$result" == "" ]; then result="root"; fi
    eval $__resultvar="'$result'"
}

capture_password() {
    local result=""
    printf "${magenta}Enter password (Password#1): ${reset}"
    local __resultvar=$1
    read -s result
    if [ "$result" == "" ]; then result="Password#1"; fi
    echo ""
    eval $__resultvar="'$result'"
}

function valid_ip() {
    local  ip=$1
    local  stat=1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

concourse_login() {
    printf "${cyan}Logging in to concourse.... "
    local i=0
    local o=0
    while [[ $i -lt 1 ]]
    do
        fly --target main login --concourse-url=http://localhost:8080 -u test -p test > /dev/null 2>&1
        if [ $? -eq 0 ]
        then
            success
            ((i++))
        else
            ((o++))
            if [ $o -eq 5 ]
            then
                success
                ((i++))
            fi
            sleep 2
        fi
    done
}

set_swarm_pipeline() {
    printf "${cyan}Creating yo damn shit!.... ${reset}"
    fly --target main set-pipeline -p build -c pipeline.yml -n > /dev/null 2>&1
    success
    printf "${cyan}Unpausing yo damn shit!.... ${reset}"
    fly --target main unpause-pipeline -p build > /dev/null 2>&1
    success
    printf "${cyan}Deploying yo damn shit!.... ${reset}"
    fly --target main trigger-job --job=build/deploy-swarm > /dev/null 2>&1
    success
}

capture_ntp_server() {
    local result=""
    printf "${magenta}Enter NTP Server (0.us.pool.ntp.org): ${reset}"
    local __resultvar=$1
    read result
    if [ "$result" == "" ]; then result="0.us.pool.ntp.org"; fi
    eval $__resultvar="'$result'"
}

function join_by { local IFS="$1"; shift; echo "$*"; }

vault_create_policy() {
    printf "${cyan}Create vault policy.... "
    echo 'path "concourse/*" {
  policy = "read"
}' >> concourse-policy.hcl
    vault policy write -address=http://localhost:8200 concourse ./concourse-policy.hcl > /dev/null 2>&1
    success
}

if [[ $# -eq 0 ]]
then
    check_kernel kernel_version
    capture_num_servers num_servers
    capture_server_ips server_list $num_servers
    capture_username user_name
    capture_password password
    capture_ntp_server ntp_server
    docker_checks
    docker_compose_checks
    fly_checks
    vault_checks
    jq_checks
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
    create_vault_secret "concourse/main/build/" "password" $password
    create_vault_secret "concourse/main/build/" "user_name" $user_name
    create_vault_secret "concourse/main/build/" "ntp_server" $ntp_server
    create_vault_secret "concourse/main/build/" "server_list" $server_list
    concourse_login
    set_swarm_pipeline
    echo "${cyan}Vault Concourse Key: ${green}${token}${reset}"
    echo "${cyan}Vault Root Key: ${green}${roottoken}${reset}"
    printf "${cyan}Here are your server(s): "
    echo "${green}${server_list[*]}"
fi

case "$1" in
    "destroy")
        cleanup
        ;;
    *)
        echo "${red}Did you mean ./bootstrap destroy?"
        ;;
esac