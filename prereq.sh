#!/bin/bash

red=`tput setaf 1`
green=`tput setaf 2`
reset=`tput sgr0`
check="\xE2\x9C\x94"
cross="\xE2\x9C\x98"

print_check() {
    printf "${green}${check}\n${reset}"
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
        exit 1
    fi
}

yum_checks() {
    local tool="yum"
    local __resultvar=$1
    local result=1
    command -v $tool > /dev/null 2>&1 && [ -x $(command -v $tool) ]
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
    command -v $tool > /dev/null 2>&1 && [ -x $(command -v $tool) ]
    if [ $? -eq 0 ]
    then
        result=0
    fi
    eval $__resultvar="'$result'"
}

yum_steps() {
    printf "${cyan}Installing ansible with yum package manager.... ${reset}"
    sudo yum -y install epel-release > /dev/null 2>&1
    sudo yum -y install ansible > /dev/null 2>&1
    success
}

apt_steps() {
    printf "${cyan}Installing ansible with apt package manager.... ${reset}"
    sudo apt update > /dev/null 2>&1
    sudo apt -y install software-properties-common > /dev/null 2>&1
    sudo apt-add-repository --yes --update ppa:ansible/ansible > /dev/null 2>&1
    sudo apt -y install ansible > /dev/null 2>&1
    success
}

install_prereqs() {
    printf "${cyan}Running pre-req install playbook.... ${reset}"
    curl https://raw.githubusercontent.com/EMC-Underground/project_colfax/${branch}/playbook.yml -o /tmp/playbook.yml > /dev/null 2>&1
    ansible-playbook /tmp/playbook.yml --tags $install_tags > /dev/null 2>&1
    success
}

cleanup() {
    [ -f /tmp/playbook.yml ] && rm /tmp/playbook.yml > /dev/null 2>&1
}

main() {
    local yum apt
    yum_checks yum
    apt_checks apt
    [ $yum -eq 0 ] && yum_steps
    [ $apt -eq 0 ] && apt_steps
    install_prereqs
}

branch="master"
[ $2 ] && branch=$2
install_tags=$1
main
cleanup
