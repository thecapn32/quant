Vagrant.configure("2") do |config|

  # OS to use for the VM
  config.vm.box = "ubuntu/zesty64"

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

  # apply some fixes to the VM OS, update it, and install some tools
  config.vm.provision "shell", inline: <<-SHELL
    export DEBIAN_FRONTEND=noninteractive

    # update the box
    apt-get update
    apt-get -y dist-upgrade
    apt-get -y autoremove
    apt-get -y autoclean

    # install some tools that are needed
    apt-get -y install git tmux ninja-build libev-dev libssl-dev g++ fish \
      pkg-config htop silversearcher-ag linux-tools-common linux-tools-generic \
      gdb valgrind mercurial libhttp-parser-dev

    # install recent cmake
    wget -q https://cmake.org/files/v3.9/cmake-3.9.1-Linux-x86_64.sh
    sh cmake-3.9.1-Linux-x86_64.sh --skip-license --prefix=/usr/local

    # change shell to fish
    chsh -s /usr/bin/fish ubuntu
  SHELL
end
