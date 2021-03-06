#!/bin/bash

export BRANCH="master"
#############################################
# Load in the config file
#############################################
source <(curl -fsSL https://raw.githubusercontent.com/EMC-Underground/project_colfax/${BRANCH}/bin/config)

#############################################
# Load in the generate file
#############################################
source <(curl -fsSL https://raw.githubusercontent.com/EMC-Underground/project_colfax/${BRANCH}/bin/generate)

#############################################
# Load in the software check functions
#############################################
source <(curl -fsSL https://raw.githubusercontent.com/EMC-Underground/project_colfax/${BRANCH}/bin/software_checks)

#############################################
# Load in the vault related functions
#############################################
source <(curl -fsSL https://raw.githubusercontent.com/EMC-Underground/project_colfax/${BRANCH}/bin/vault)

#############################################
# Load in the concourse related functions
#############################################
source <(curl -fsSL https://raw.githubusercontent.com/EMC-Underground/project_colfax/${BRANCH}/bin/concourse)

#############################################
# Load in the input related functions
#############################################
source <(curl -fsSL https://raw.githubusercontent.com/EMC-Underground/project_colfax/${BRANCH}/bin/input)

pull_repo() {
    local repo_url=$1 repo_name=`echo $1 | awk -F'/' '{print $NF}' | awk -F'.' '{print $1}'`
    printf "${cyan}Cloning ${repo_name} repo.... "
    if [ -d "${temp_location}/${repo_name}" ]
    then
        rm ${temp_location}/$repo_name > /dev/null 2>&1
    fi
    git clone $repo_url ${temp_location}/$repo_name > /dev/null 2>&1
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
    [ -d "${temp_location}/vault-consul-docker" ] && sudo rm -Rf ${temp_location}/vault-consul-docker > /dev/null 2>&1
    [ -d "${temp_location}/concourse-docker" ] && sudo rm -Rf ${temp_location}/concourse-docker > /dev/null 2>&1
    [ -f "${temp_location}/concourse-policy.hcl" ] && sudo rm ${temp_location}/concourse-policy.hcl > /dev/null 2>&1
    [ -f "${temp_location}/pipeline.yml" ] && sudo rm ${temp_location}/pipeline.yml > /dev/null 2>&1
    [ -f "${temp_location}/vars.yml" ] && sudo rm ${temp_location}/vars.yml > /dev/null 2>&1
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
    [ -z ${password+x} ] && capture_password password
    [ -z ${temp_location+x} ] && capture_temp_location temp_location
    capture_generic_data
    [[ "$persistence" == "y" ]] && [ -z ${persistence_driver+x} ] && capture_persistence_driver persistence_driver
    [[ "$persistence_driver" == "nfs" ]] && [ -z ${nfs_server+x} ] && capture_nfs_server nfs_server
    [[ "$persistence_driver" == "nfs" ]] && [ -z ${nfs_share+x} ] && capture_nfs_share nfs_share
    [[ "$persistence_driver" == "vxflex" ]] && capture_vxflex_data
}

capture_generic_data() {
    local vars=( "user_name" "root" "ntp_server" "0.us.pool.ntp.org" "persistence" "n" )
    local i=0
    while [[ $i -lt ${#vars[@]} ]]
    do
        local var_name="${vars[$i]}"
        i=$((i+1))
        local var_default=${vars[$i]}
        eval var_value=\$$var_name
        [ "${var_value}" == "" ] && capture_the_data $var_name $var_default
        i=$((i+1))
    done
}

capture_vxflex_data() {
    local vars=( "gateway_ip" "" "gateway_port" 443 "system_name" "scaleio" "protection_domain" "pd1" "storage_pool" "sp1" "username" "admin" "password" "Password#1" )
    echo "---==Capture VxFlex Info==---"
    local i=0
    while [[ $i -lt ${#vars[@]} ]]
    do
        local var_name="vxflex_${vars[$i]}"
        i=$((i+1))
        local var_default=${vars[$i]}
        eval var_value=\$$var_name
        [ "${var_value}" == "" ] && capture_the_data $var_name $var_default
        i=$((i+1))
    done
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
    vault_vxflex_secrets
    vault_nfs_secrets
    create_vault_secret "concourse/main/build/" "persistence_driver" "$persistence_driver"
    create_vault_secret "concourse/main/build/" "temp_location" "$temp_location"
    create_vault_secret "concourse/main/build/" "swarm_tags" "swarm,${persistence_driver}"
    create_vault_secret "concourse/main/build/" "password" $password
    create_vault_secret "concourse/main/build/" "user_name" $user_name
    create_vault_secret "concourse/main/build/" "ntp_server" $ntp_server
    create_vault_secret "concourse/main/build/" "server_list" $(join_by "," ${server_list[@]})
    create_vault_secret "concourse/main/build/" "concourse_username" "test"
    create_vault_secret "concourse/main/build/" "concourse_password" "test"
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
    printf "${blue}##         ${magenta}Proxy URL: ${green}http://proxy.${dns_suffix}\n"
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
