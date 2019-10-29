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


install_ansible() {

}

if [[ $# -eq 0 ]]
then
    install_ansible
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
    printf "${cyan}Here are your server(s): "
    echo "${green}${server_list[*]}"
fi

case "$1" in
    "destroy")
        cleanup
        ;;
    "")
        echo "${green}FIN${reset}"
        ;;
    *)
        echo "${red}Did you mean ./bootstrap destroy?${reset}"
        ;;
esac
