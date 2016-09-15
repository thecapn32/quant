cmake_minimum_required(VERSION 3.6)

find_program (VAGRANT vagrant)

add_custom_target(vagrant-up ${VAGRANT} up)

# https://github.com/google/proto-quic will be checked out here
set(QUIC /vagrant/proto-quic)

include(ExternalProject)
ExternalProject_Add(proto-quic
  DEPENDS vagrant-up
	GIT_REPOSITORY https://github.com/google/proto-quic.git
  PREFIX proto-quic
  # UPDATE_DISCONNECTED 1
  # CONFIGURE_COMMAND ""
  CONFIGURE_COMMAND ${VAGRANT} ssh -c "echo ttf-mscorefonts-installer msttcorefonts/accepted-mscorefonts-eula select true \| sudo debconf-set-selections $<SEMICOLON> ${QUIC}/src/build/install-build-deps.sh --no-syms --no-arm --no-chromeos-fonts --no-nacl --no-prompt"
  BUILD_COMMAND ${VAGRANT} ssh -c "export PATH=$PATH:${QUIC}/depot_tools $<SEMICOLON> cd ${QUIC}/src $<SEMICOLON> gclient runhooks \&\& ninja -v -C out/Release quic_client quic_server net_unittests"
  INSTALL_COMMAND ""
)

add_test(quic_server ${VAGRANT} ssh -c 'ls -l /')
