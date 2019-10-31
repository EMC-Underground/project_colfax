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
    sudo apt update
    sudo apt -y install software-properties-common
    sudo apt-add-repository --yes --update ppa:ansible/ansible
    sudo apt -y install ansible
}

install_prereqs() {
    curl https://raw.githubusercontent.com/EMC-Underground/project_colfax/${branch}/playbook.yml -o /tmp/playbook.yml > /dev/null 2>&1
    echo "ansible-playbook /tmp/playbook.yml --tags ${install_tags}"
    ansible-playbook /tmp/playbook.yml --tags $install_tags
}

cleanup() {
    [ -f /tmp/playbook.yml ] && rm /tmp/playbook.yml > /dev/null 2>&1
}

get_args() {
    local var
    for var in "$@"
    do
        echo $var
        if [[ " ${tags[@]} " =~ " ${var} " ]]
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
for var in $@
do
    echo $var
done
tags=( "fly" "docker" "docker-compose" "vault" "git" "kernel" "jq" )
[ $2 ] && branch="dev"
install_tags=$1
main
cleanup
