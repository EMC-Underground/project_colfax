#!/bin/bash

#############################################
# Load in the config file
#############################################
source <(curl -fsSL https://raw.githubusercontent.com/EMC-Underground/project_colfax/dev/bin/config)

#############################################
# Load in the software check functions
#############################################
source <(curl -fsSL https://raw.githubusercontent.com/EMC-Underground/project_colfax/dev/bin/software_checks)

#############################################
# Load in the vault related functions
#############################################
source <(curl -fsSL https://raw.githubusercontent.com/EMC-Underground/project_colfax/dev/bin/vault)

#############################################
# Load in the concourse related functions
#############################################
source <(curl -fsSL https://raw.githubusercontent.com/EMC-Underground/project_colfax/dev/bin/concourse)

#############################################
# Load in the input related functions
#############################################
source <(curl -fsSL https://raw.githubusercontent.com/EMC-Underground/project_colfax/dev/bin/input)

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
    [ -f "/tmp/vars.yml" ] && sudo rm /tmp/vars.yml > /dev/null 2>&1
    print_check
}

build_docker_network() {
    printf "${cyan}Building docker bridge network.... "
    docker network create comms > /dev/null 2>&1
    success
}

print_title() {
    printf "${blue}---==Project Colfax ${app_version}==---\n"
    printf "This project is aimed to deploy a Dell Tech Automation Platform\n"
    printf "Please report issues to https://github.com/EMC-Underground/project_colfax${reset}\n\n"
}

capture_data() {
    [ ${#server_list[@]} -eq 0 ] && capture_num_servers num_servers
    [ ${#server_list[@]} -eq 0 ] && input_server_ips server_list $num_servers
    [ -z ${user_name+x} ] && capture_username user_name
    [ -z ${password+x} ] && capture_password password
    [ -z ${ntp_server+x} ] && capture_ntp_server ntp_server
}

vault_setup() {
    pull_repo `generate_repo_url "github.com" "EMC-Underground" "vault-consul-docker"`
    build_deploy_vault
    vault_init keys
    unseal=`echo $keys | jq -r .unseal_keys_b64[0]`
    roottoken=`echo $keys | jq -r .root_token`
    vault_unseal $unseal
    vault_login $roottoken
    vault_create_store
    vault_create_policy
    vault_create_token token
    export VAULT_CLIENT_TOKEN=$token
    create_vault_secret "concourse/main/build/" "password" $password
    create_vault_secret "concourse/main/build/" "user_name" $user_name
    create_vault_secret "concourse/main/build/" "ntp_server" $ntp_server
    create_vault_secret "concourse/main/build/" "server_list" $(join_by "," ${server_list[@]})
    create_vault_secret "concourse/main/" "dnssuffix" ${dns_suffix}
    create_vault_secret "concourse/main/" "dockerhost" ${server_list[0]}
    create_vault_secret "concourse/main/build/" "tempvaultroottoken" ${roottoken}
    create_vault_secret "concourse/main/build/" "tempvaultip" ${ip}
    [[ $ssh_repos -eq 0 ]] && ssh_key_value="$(<$ssh_key)" && create_vault_secret "concourse/main/build/" "ssh_key" "$ssh_key_value"
}

concourse_setup() {
    pull_repo `generate_repo_url "github.com" "EMC-Underground" "concourse-docker"`
    generate_keys
    deploy_concourse
    build_pipeline
    concourse_login
    set_swarm_pipeline
}

print_finale() {
    printf "${blue}###################### ${magenta}VAULT INFO ${blue}########################\n"
    printf "${blue}##              ${magenta}URL: ${green}http://${ip}:8200\n"
    printf "${blue}##       ${magenta}Root Token: ${green}${roottoken}\n"
    printf "${blue}##  ${magenta}Concourse Token: ${green}${token}\n"
    printf "${blue}##########################################################\n"
    printf "\n"
    printf "${blue}#################### ${magenta}CONCOURSE INFO ${blue}######################\n"
    printf "${blue}##              ${magenta}URL: ${green}http://${ip}:8080\n"
    printf "${blue}##             ${magenta}User: ${green}test\n"
    printf "${blue}##         ${magenta}Password: ${green}test\n"
    printf "${blue}##########################################################${reset}\n"
    printf "\n"
    printf "${blue}###################### ${magenta}SWARM INFO ${blue}########################\n"
    printf "${blue}##              ${magenta}If running from a remote CLI\n"
    printf "${blue}##           ${green}export DOCKER_HOST=${server_list[0]}\n"
    printf "${blue}##         ${magenta}Proxy URL: ${green}https://proxy.${dns_suffix}\n"
    printf "${blue}##########################################################${reset}\n"
}

main() {
    print_title
    ip=`ip -o route get to 8.8.8.8 | sed -n 's/.*src \([0-9.]\+\).*/\1/p'`
    export DNS_URL=$ip
    software_pre_reqs
    capture_data
    [ -z ${dns_suffix+x} ] && dns_suffix="${server_list[0]}.xip.io"
    generate_config
    [[ $ssh_repos -eq 0 ]] && check_ssh_key
    build_docker_network
    vault_setup
    concourse_setup
}

generate_repo_url() {
    local src_url=$1 repo_user=$2 repo_name=$3
    if [[ ssh_repos -eq 0 ]]
    then
        printf "git@${src_url}:${repo_user}/${repo_name}.git"
    else
        printf "https://${src_url}/${repo_user}/${repo_name}.git"
    fi
}

check_ssh_key() {
    printf "${cyan}Checking for SSH key.... "
    [ -f $ssh_key ]
    success
}

generate_config() {
    printf "${cyan}Checking for config file.... "
    [ ! -d $HOME/.colfax ] && mkdir $HOME/.colfax
    if [ ! -f $HOME/.colfax/config.json ]
    then
        echo "{" > $HOME/.colfax/config.json
        echo "    \"jobs\": [" >> $HOME/.colfax/config.json
        echo "`generate_json_pipeline_job "swarm" "github.com" "EMC-Underground" "ansible_install_dockerswarm" "dev"`," >> $HOME/.colfax/config.json
        echo "`generate_json_pipeline_job "network" "github.com" "EMC-Underground" "project_colfax" "dev"`," >> $HOME/.colfax/config.json
        echo "`generate_json_pipeline_job "proxy" "github.com" "EMC-Underground" "service_proxy" "master"`," >> $HOME/.colfax/config.json
        echo "`generate_json_pipeline_job "consul" "github.com" "EMC-Underground" "service_consul" "master"`," >> $HOME/.colfax/config.json
        echo "`generate_json_pipeline_job "vault" "github.com" "EMC-Underground" "service_vault" "master"`," >> $HOME/.colfax/config.json
        echo "`generate_json_pipeline_job "concourse" "github.com" "EMC-Underground" "service_concourse" "master"`" >> $HOME/.colfax/config.json
        echo "    ]" >> $HOME/.colfax/config.json
        echo "}" >> $HOME/.colfax/config.json
    fi
    jq type $HOME/.colfax/config.json > /dev/null 2>&1
    success
}

generate_json_pipeline_job() {
    local name=$1 src_url=$2 repo_user=$3 repo_name=$4 repo_branch=$5
    printf "        {
            \"job_name\": \"${name}\",
            \"src_url\": \"${src_url}\",
            \"repo_user\": \"${repo_user}\",
            \"repo_name\": \"${repo_name}\",
            \"repo_branch\": \"${repo_branch}\"
        }"
}

read_config() {
    local config_file=$HOME/.colfax/config.json config="" job_length=0
    [ $1 ] && config_file=$1
    config="$(<$config_file)"
    job_length=`echo "$config" | jq '.jobs | length'`
    for (( i=0; i<${job_length}; i++ ))
    do
        local job_name=`echo "$config" | jq -r .jobs.[$i].job_name`
        local src_url=`echo "$config" | jq -r .jobs.[$i].src_url`
        local repo_user=`echo "$config" | jq -r .jobs.[$i].repo_user`
        local repo_name=`echo "$config" | jq -r .jobs.[$i].repo_name`
        local repo_branch=`echo "$config" | jq -r .jobs.[$i].repo_branch`
        add_job $job_name `generate_repo_url $src_url $repo_user $repo_name` $repo_branch
    done
    if [[ `echo $config | jq .persistance` != "null" ]]
    then
      volume_driver=`echo "$config" | jq -r .persistance.driver`
      volume_driver_opts=`echo "$config" | jq -r .persistance.driver_opts`
      create_vault_secret "concourse/main/build/" "volume_driver" $volume_driver
      create_vault_secret "concourse/main/build/" "volume_driver_opts" $volume_driver_opts
    fi
}

usage=$(cat << EOM
$(basename "$0") [-h] Project Colfax
An IaC platform for Dell Technology offerings.
Options:
    [ --servers | -s ]      Comma delimited list of servers where the platform will deploy
    [ --username | -u ]     Username used to deploy the platform on the nodes provided
    [ --password | -p ]     Password used to deploy the platform on the nodes provided
    [ --ntp | -n ]          NTP Server to use on the nodes provided
    [ --enable-ssh-repos ]  Any repositories used will use their ssh address. Requires SSH private key
    [ --ssh-private-key ]   Path to your github private key (Default: $HOME/.ssh/id_rsa)
    [ --config ]            Path to your config file
    [ --custom-dns-suffix ] Add a custom dns suffix for the reverse proxy to use. (Default: [server_ip].xip.io)
    [ --generate-config ]   Create config file example
    [ --no-cleanup ]        Leave all artifacts behind (mostly in tmp)
    [ destroy | --destroy ] Destroy and cleanup the local bootstrap leaves platform
    [ --version | -v ]      Print app current version
EOM
)
while [[ $# -gt 0 ]]
do
    key="$1"
    case $key in
        "destroy"|"--destroy"|"-d")
            print_title
            cleanup
            destroy
            exit 0
            ;;
        "generate-config"|"--generate-config")
            print_title
            printf "${red}Generate default config (This moves any existing config to config.orig)? (yes/no) "
            read regen
            if [ $regen == "yes" ]
            then
                [ -f $HOME/.colfax/config.json ] && mv $HOME/.colfax/config.json $HOME/.colfax/config.json.orig
                generate_config
            fi
            exit 0
            ;;
        "--servers"|"-s")
            servers=$2
            pre_server_list=( ${servers//,/ } )
            server_count=${#pre_server_list[@]}
            [ $((server_count%2)) -eq 0 ] && echo "${red}Please enter an odd number of servers" && exit 1
            for item in ${pre_server_list[@]}
            do
                validate_ip $item
                [ $? -ne 0 ] && echo "${green}Example: --servers 10.0.0.10,10.0.0.11,10.0.0.12${reset}" && exit 1
                server_list=( "${server_list[@]}" $item )
            done
            shift
            shift
            ;;
        "--username"|"-u"|"--user")
            user_name=$2
            shift
            shift
            ;;
        "--password"|"-p"|"--pass")
            password=$2
            shift
            shift
            ;;
        "--ntp"|"-n"|"--ntpserver")
            ntp_server=$2
            shift
            shift
            ;;
        "--enable-ssh-repos")
            ssh_repos=0
            shift
            ;;
        "--custom-dns-suffix")
            dns_suffix=$2
            shift
            shift
            ;;
        "--ssh-private-key")
            ssh_key=$2
            shift
            shift
            ;;
        "--no-cleanup")
            no_cleanup=true
            shift
            shift
            ;;
        "--version"|"-v")
            printf "${app_version}\n"
            exit 0
            ;;
        "--help"|"-h")
            printf "${usage}\n"
            exit 0
            ;;
        *)
            ;;
    esac
done

main
if [ "$no_cleanup" = false ]; then cleanup; fi
print_finale
