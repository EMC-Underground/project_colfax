# -*- mode: ruby -*-
# vi: set ft=ruby :

# Every Vagrant development environment requires a box. You can search for
# boxes at https://atlas.hashicorp.com/search.
BOX_IMAGE = "geerlingguy/centos7"
NODE_COUNT = 2

Vagrant.configure("2") do |config|
  config.vm.define "master" do |subconfig|
    subconfig.vm.box = BOX_IMAGE
    subconfig.vm.hostname = "master"
    subconfig.vm.network :private_network, ip: "192.168.33.5"
  end

  (1..NODE_COUNT).each do |i|
    config.vm.define "node#{i}" do |subconfig|
      subconfig.vm.box = BOX_IMAGE
      subconfig.vm.hostname = "node#{i}"
      subconfig.vm.network :private_network, ip: "192.168.33.#{i + 5}"
    end
  end

  config.vm.provider "virtualbox" do |v|
    v.memory = 512
    v.cpus = 1
  end
  # Install avahi on all machines
  config.vm.provision "shell", inline: <<-SHELL
    yum install -y epel-release
    yum install -y avahi-tools nss-mdns open-vm-tools
    systemctl start avahi-daemon
  SHELL
end
