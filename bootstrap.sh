#!/bin/bash

# Set Color Variables
red=`tput setaf 1`
green=`tput setaf 2`
cyan=`tput setaf 6`
blue=`tput setaf 4`
magenta=`tput setaf 5`
reset=`tput sgr0`
check="\xE2\x9C\x94"
cross="\xE2\x9C\x98"
min_dv="18.09"
min_dcv="1.24"
min_vv="1.2.3"
min_fv="5.5.1"
min_jv="1.5"
min_gv="1.5"
app_version="v0.4.2"
failed_software=()

function version { echo "$@" | awk -F. '{ printf("%03d%03d%03d\n", $1,$2,$3); }'; }

check_kernel() {
    printf "${cyan}Kernel Version... ${reset}"
    local  __resultvar=$1
    local result=`uname -r | awk -F- '{print $1}'`
    printf "${green}${result}\n"
    local maj_ver=`echo $result | cut -d'.' -f1`
    eval $__resultvar="'$maj_ver'"
}

print_check() {
    printf "${green}${check}\n${reset}"
}

print_version() {
    case $2 in
        good)
            printf "${green}${1}\n${reset}"
            ;;
        bad)
            if [ $1 == "0" ]
            then
                printf "${red}Not Installed | minimum ver. ${3}\n${reset}"
            else
                printf "${red}${1} | minimum ver. ${3}\n${reset}"
            fi
            ;;
    esac
}

print_cross() {
    printf "${red}${cross}\n${reset}"
}

success() {
    if [ $? -eq 0 ]
    then
        print_check
    else
        print_cross
        printf "\n${blue}You may artifacts leftover from a previous run.\n"
        printf "Try running ${green}\"./bootstrap.sh destroy\"${blue} Then try again${reset}\n"
        exit 1
    fi
}

success_version() {
    local curr_ver=$1 req_ver=$2 tool=$3
    if [ "$(version ${curr_ver})" -ge "$(version ${req_ver})" ]
    then
        print_version $curr_ver "good" $req_ver
    else
        print_version $curr_ver "bad" $req_ver
        versions=1
        failed_software=( "${failed_software[@]}" "${tool}" )
    fi
}

docker_checks() {
    local tool="docker"
    local dv=0
    printf "${cyan}Checking ${tool} version.... "
    command -v $tool > /dev/null 2>&1
    if [ $? -eq 0 ]
    then
        dv=`${tool} --version | awk -F'[, ]' '{print $3}'`
    fi
    success_version $dv $min_dv $tool
}

docker_compose_checks() {
    local tool="docker-compose"
    local dcv=0
    printf "${cyan}Checking ${tool} version.... "
    command -v $tool > /dev/null 2>&1
    if [ $? -eq 0 ]
    then
        dcv=`$tool version | awk -F'[, ]' 'NR==1 {print $3}'`
    fi
    success_version $dcv $min_dcv $tool
}

vault_checks() {
    local tool="vault"
    local vv=0
    printf "${cyan}Checking ${tool} version.... "
    command -v $tool > /dev/null 2>&1
    if [ $? -eq 0 ]
    then
        vv=`vault -v | awk '{print substr($2,2)}'`
    fi
    success_version $vv $min_vv $tool
}

jq_checks() {
    local tool="jq"
    local jv=0
    printf "${cyan}Checking ${tool} version.... "
    command -v $tool > /dev/null 2>&1
    if [ $? -eq 0 ]
    then
        jv=`jq --version | awk -F- '{print $2}'`
    fi
    success_version $jv $min_jv $tool
}

fly_checks() {
    local tool="fly"
    local fv=0
    printf "${cyan}Checking ${tool} version.... "
    command -v $tool > /dev/null 2>&1
    if [ $? -eq 0 ]
    then
        fv=`fly --version`
    fi
    success_version $fv $min_fv $tool
}

git_checks() {
    local tool="git"
    local gv=0
    printf "${cyan}Checking ${tool} version.... "
    command -v $tool > /dev/null 2>&1
    if [ $? -eq 0 ]
    then
        gv=`git --version | awk '{print $NF}'`
    fi
    success_version $gv $min_gv $tool
}

pull_repo() {
    local repo_url=$1 repo_name=`echo $1 | awk -F'/' '{print $NF}' | awk -F'.' '{print $1}'`
    printf "${cyan}Cloning ${repo_name} repo.... "
    if [ -d "/tmp/${repo_name}" ]
    then
        rm /tmp/$repo_name > /dev/null 2>&1
    fi
    git clone $repo_url /tmp/$repo_name > /dev/null 2>&1
    success
}

generate_keys() {
    printf "${cyan}Generating Concourse Keys.... "
    bash ./keys/generate > /dev/null 2>&1
    success
}

deploy_concourse() {
    printf "${cyan}Deploying Concourse.... "
    ip=`ip -o route get to 8.8.8.8 | sed -n 's/.*src \([0-9.]\+\).*/\1/p'`
    export DNS_URL=$ip
    #export DNS_URL="localhost"
    case $kernel_version in
    4|5)
        export STORAGE_DRIVER=overlay
        ;;
    3)
        export STORAGE_DRIVER=btrfs
        ;;
    *)
        print_cross;;
    esac
    cd /tmp/concourse-docker
    docker-compose up -d > /dev/null 2>&1
    success
    cd - > /dev/null 2>&1
}

build_deploy_vault() {
    printf "${cyan}Deploying Vault.... "
    cd /tmp/vault-consul-docker
    docker-compose up -d --build > /dev/null 2>&1
    success
    cd - > /dev/null 2>&1
}

destroy() {
    printf "${cyan}Destroying vault.... "
    docker kill `docker ps -q --filter "name=vault-consul-docker"` > /dev/null 2>&1
    print_check
    printf "${cyan}Destroying concourse.... "
    docker kill `docker ps -q --filter "name=concourse-docker"` > /dev/null 2>&1
    print_check
    printf "${cyan}Pruning docker containers and networks.... "
    docker system prune -f > /dev/null 2>&1
    print_check
    printf "${cyan}Pruning docker volumes.... "
    docker volume prune -f > /dev/null 2>&1
    print_check
}

cleanup() {
    printf "${cyan}Cleaning up files and folders.... "
    [ -d "/tmp/vault-consul-docker" ] && sudo rm -Rf /tmp/vault-consul-docker > /dev/null 2>&1
    [ -d "/tmp/concourse-docker" ] && sudo rm -Rf /tmp/concourse-docker > /dev/null 2>&1
    [ -f "/tmp/concourse-policy.hcl" ] && sudo rm /tmp/concourse-policy.hcl > /dev/null 2>&1
    [ -f "/tmp/pipeline.yml" ] && sudo rm /tmp/pipeline.yml > /dev/null 2>&1
    print_check
}

vault_init() {
    printf "${cyan}Initializing Vault.... "
    local  __resultvar=$1
    local i=0
    local o=0
    while [[ $i -lt 1 ]]
    do
        vault operator init -address=http://localhost:8200 -status > /dev/null 2>&1
        if [[ $? -eq 2 || $? -eq 0 ]]
        then
            ((i++))
        else
            if [ $o -eq 4 ]
            then
                success
                ((i++))
            else
                ((o++))
                sleep 2
            fi
        fi
    done
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
}' >> /tmp/concourse-policy.hcl
    vault policy write -address=http://localhost:8200 concourse /tmp/concourse-policy.hcl
    success
}

pipeline_add_job() {
    local name=$1 repo_url=$2 repo_branch=$3
    local resource="  - name: ${name}_repo
    type: git
    source:
      uri: ${repo_url}
      branch: ${repo_branch}"
    local job="  - name: ${name}_job
    public: true
    plan:
      - get: ${name}_repo
      - task: deploy_${name}
        file: ${name}_repo/task/task.yml"
    echo -e "${resource}\n$(cat pipeline.yml)" > pipeline.yml
    echo -e "${job}\n" >> pipeline.yml
}

build_pipeline() {
    printf "${cyan}Creating pipeline definition.... ${reset}"
    echo -e "jobs:" > pipeline.yml
    pipeline_add_job "swarm" "https://github.com/EMC-Underground/ansible_install_dockerswarm" "dev"
    pipeline_add_job "concourse" "https://github.com/EMC-Underground/service_concourse" "master"
    echo -e "resources:\n$(cat pipeline.yml)" > pipeline.yml
    echo -e "---\n$(cat pipeline.yml)" > pipeline.yml
    [ -f pipeline.yml ]
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
    local __resultvar=$1
    until [ $((result%2)) -ne 0 ]
    do
        printf "${magenta}How many servers will you use (odd numbers only): ${reset}"
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
    sleep 2
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
    concourse_login
    printf "${cyan}Creating build pipeline.... ${reset}"
    fly --target main set-pipeline -p build -c /tmp/pipeline.yml -n > /dev/null
    success
    printf "${cyan}Unpausing the build pipeline.... ${reset}"
    fly --target main unpause-pipeline -p build > /dev/null
    success
    printf "${cyan}Triggering the build-swarm job.... ${reset}"
    fly --target main trigger-job --job=build/swarm_job > /dev/null
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

vault_create_policy() {
    printf "${cyan}Create vault policy.... "
    echo 'path "concourse/*" {
  policy = "read"
}' >> concourse-policy.hcl
    vault policy write -address=http://localhost:8200 concourse /tmp/concourse-policy.hcl > /dev/null 2>&1
    success
}

print_title() {
    printf "${blue}---==Project Colfax ${app_version}==---\n"
    printf "This project is aimed to deploy a Dell Tech Automation Platform\n"
    printf "Please report issues to https://github.com/EMC-Underground/project_colfax${reset}\n\n"
}

function join_by { local IFS="$1"; shift; echo "$*"; }

software_pre_reqs() {
    versions=0
    git_checks
    docker_checks
    docker_compose_checks
    fly_checks
    vault_checks
    jq_checks
    check_kernel kernel_version
    [ $kernel_version -lt 4 ] && failed_software=( "${failed_software[@]}" "kernel" )
    if [ $versions -eq 1 ]
    then
        printf "${red}\n##### Pre-Reqs not met! #####${reset}\n\n"
        printf "${green}This command will run an Ansible Playbook to install\n"
        printf "all pre-requisite software (inc. Ansible)\n\n"
        IFS=","
        echo "${failed_software[*]}"
        exit 1
    fi
    printf "\n${green}All Pre-Reqs met!${reset}\n\n"
}

main() {
    print_title
    software_pre_reqs
    capture_num_servers num_servers
    capture_server_ips server_list $num_servers
    capture_username user_name
    capture_password password
    capture_ntp_server ntp_server
    build_docker_network
    pull_repo "https://github.com/EMC-Underground/vault-consul-docker.git"
    build_deploy_vault
    vault_init keys
    unseal=`echo $keys | jq -r .unseal_keys_b64[0]`
    roottoken=`echo $keys | jq -r .root_token`
    vault_unseal $unseal
    vault_login $roottoken
    vault_create_store
    vault_create_policy
    vault_create_token token
    pull_repo "https://github.com/EMC-Underground/concourse-docker.git"
    generate_keys
    export VAULT_CLIENT_TOKEN=$token
    deploy_concourse
    create_vault_secret "concourse/main/build/" "password" $password
    create_vault_secret "concourse/main/build/" "user_name" $user_name
    create_vault_secret "concourse/main/build/" "ntp_server" $ntp_server
    create_vault_secret "concourse/main/build/" "server_list" $server_list
    build_pipeline
    set_swarm_pipeline
    echo "${cyan}Vault Concourse Key: ${green}${token}${reset}"
    echo "${cyan}Vault Root Key: ${green}${roottoken}${reset}"
    echo "${cyan}Concourse URL: ${green}http://$DNS_URL:8080${reset}"
    echo "${cyan}Vault URL: ${green}http://$DNS_URL:8200${reset}"
    printf "${cyan}Here are your server(s): ${reset}"
    echo "${green}${server_list[*]}${reset}"
}

case "$0" in
    "destroy")
        cleanup
        destroy
        exit 0
        ;;
    *)
        ;;
esac

main
cleanup
