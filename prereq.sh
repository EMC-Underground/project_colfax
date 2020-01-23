#!/bin/bash

red=`tput setaf 1`
green=`tput setaf 2`
reset=`tput sgr0`
cyan=`tput setaf 6`
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

ansible_checks() {
    local tool="ansible-playbook"
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
    printf "${cyan}Kickoff ${branch} pre-req install playbook.... ${reset}"
    success
    curl https://raw.githubusercontent.com/EMC-Underground/project_colfax/${branch}/playbook.yml -o /tmp/playbook.yml > /dev/null 2>&1
    ansible-playbook /tmp/playbook.yml --inventory=127.0.0.1, --tags $install_tags
}

cleanup() {
    [ -f /tmp/playbook.yml ] && rm /tmp/playbook.yml > /dev/null 2>&1
}

main() {
    local yum apt ansible
    yum_checks yum
    apt_checks apt
    ansible_checks ansible
    if [ $ansible -ne 0 ]
    then
        [ $yum -eq 0 ] && yum_steps
        [ $apt -eq 0 ] && apt_steps
    fi
    install_prereqs
}

branch="master"
install_tags=$1
[ $2 ] && branch=$2
main
cleanup
if [[ " ${install_tags[@]} " =~ " kernel " ]]
then
    exit 0
fi
