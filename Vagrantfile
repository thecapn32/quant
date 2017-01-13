# This is a config file for vagrant (https://www.vagrantup.com/),
# which will install an ubuntu/xenial64 VM, inside which we'll build
# and run the proto-quic quic_server (https://github.com/google/proto-quic)
# to test our implementation against.

Vagrant.configure("2") do |config|
  config.vm.hostname = "proto-quic"

  # OS to use for the VM
  config.vm.box = "ubuntu/yakkety64"

  # don't always check for box updates
  config.vm.box_check_update = false

  # hardware configuration of the VM
  config.vm.provider "virtualbox" do |vb|
    vb.gui = false
    vb.memory = "1024"
    vb.cpus = 2
    vb.linked_clone = true
    vb.name = config.vm.hostname

    # use virtio for uplink, in case there is an issue with netmap's e1000
    vb.customize ["modifyvm", :id, "--nictype1", "virtio"]

    # per-VM serial log
    vb.customize ["modifyvm", :id, "--uartmode1", "file",
      File.join(Dir.pwd, "%s-console.log" % config.vm.hostname)]

    # better clock synchronization (to within 100ms)
    vb.customize [ "guestproperty", "set", :id,
      "/VirtualBox/GuestAdd/VBoxService/--timesync-set-threshold", 100 ]
 end

  # quic_server will listen on 127.0.0.1:6121 inside the VM
  config.vm.network "forwarded_port", guest: 6121, host: 6121, protocol: "udp"

  # apply some fixes to the VM OS, update it, and install some tools
  config.vm.provision "shell", inline: <<-SHELL
    export DEBIAN_FRONTEND=noninteractive

    # update the box
    apt-get update
    # apt-get -y dist-upgrade
    apt-get -y autoremove
    apt-get -y autoclean

    # install some tools that are needed
    apt-get -y install cmake cmake-curses-gui git doxygen graphviz

    # and some that I often use
    apt-get -y install htop silversearcher-ag linux-tools-common \
      linux-tools-generic gdb nmap fish dwarves

    # install some tools that are needed for the tests, or that I often use
    apt-get -y install htop silversearcher-ag daemon cmake cmake-curses-gui \
      git libnss3-dev libev-dev doxygen graphviz

    # change shell to fish
    chsh -s /usr/bin/fish ubuntu
  SHELL
end
