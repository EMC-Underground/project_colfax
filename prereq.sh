#!/bin/bash

yum_checks() {
    local tool="yum"
    local __resultvar=$1
    local result=1
    command -v $tool > /dev/null 2>&1
    if [ $? -eq 0 ]
    then
        result=0
    fi
    eval $__resultvar="'$result'"
}

apt_checks() {
    local tool="apt-get"
    local __resultvar=$1
    local result=1
    command -v $tool > /dev/null 2>&1
    if [ $? -eq 0 ]
    then
        result=0
    fi
    eval $__resultvar="'$result'"
}

yum_steps() {
    sudo yum -y install epel-release > /dev/null 2>&1
    sudo yum -y install ansible > /dev/null 2>&1
}

apt_steps() {
    sudo apt update > /dev/null 2>&1
    sudo apt install software-properties-common > /dev/null 2>&1
    sudo apt-add-repository --yes --update ppa:ansible/ansible > /dev/null 2>&1
    sudo apt install ansible > /dev/null 2>&1
}

install_prereqs() {
    echo "curl https://raw.githubusercontent.com/EMC-Underground/project_colfax/${branch}/playbook.yml -o /tmp/playbook.yml"
    curl https://raw.githubusercontent.com/EMC-Underground/project_colfax/${branch}/playbook.yml -o /tmp/playbook.yml > /dev/null 2>&1
    IFS=","
    ansible-playbook /tmp/playbook.yml --tags ${install_tags[*]}
}

cleanup() {
    [ -f /tmp/playbook.yml ] && rm /tmp/playbook.yml > /dev/null 2>&1
}

get_args() {
    for arg in "$@"
    do
        if [[ " ${tags[@]} " =~ " ${arg} " ]]
        then
            [ ! $arg == "dev" ] && install_tags=( "${install_tags[@]}" "${arg}" )
            [ $arg == "dev" ] && branch="dev"
        fi
    done
}

main() {
    local yum apt
    yum_checks yum
    apt_checks apt
    if [ $yum ] ; then yum_steps ; fi
    if [ $apt ] ; then apt_steps ; fi
    install_prereqs
}

branch="master"
tags=( "fly" "docker" "docker-compose" "vault" "git" "kernel" "jq" )
install_tags=()
get_args
main
cleanup
