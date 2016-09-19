# Allow a target named "test" below, which his normally reserved by cmake
# https://github.com/ros/ros/pull/61
cmake_policy(SET CMP0037 OLD)

find_program(VAGRANT vagrant)
find_program(NC nc)
find_program(CAT cat)

# https://github.com/google/proto-quic will be checked out here
set(QUIC /vagrant/proto-quic)

# some convenience paths under ${QUIC}
set(CERTS ${QUIC}/src/net/tools/quic/certs)
set(BIN ${QUIC}/src/out/Debug)

add_custom_target(vagrant-up ${VAGRANT} up)

include(externalproject)
externalproject_add(proto-quic
  # XXX comment next line in order to update from git
  UPDATE_COMMAND ""
  EXCLUDE_FROM_ALL 1
  DEPENDS vagrant-up
  GIT_REPOSITORY https://github.com/google/proto-quic.git
  GIT_SHALLOW 1
  PREFIX proto-quic
  SOURCE_DIR proto-quic
  STAMP_DIR proto-quic-stamp
  TMP_DIR proto-quic-tmp
  CONFIGURE_COMMAND ${VAGRANT} ssh -c "\
    echo ttf-mscorefonts-installer msttcorefonts/accepted-mscorefonts-eula \
      select true | sudo debconf-set-selections && \
    ${QUIC}/src/build/install-build-deps.sh --no-syms --no-arm \
      --no-chromeos-fonts --no-nacl --no-prompt && \
    export PATH=$PATH:${QUIC}/depot_tools && \
    cd ${QUIC}/src && gclient runhooks && \
    cd ${CERTS} && ./generate-certs.sh \
  "
  BUILD_IN_SOURCE 1
  BUILD_COMMAND ${VAGRANT} ssh -c "\
    export PATH=$PATH:${QUIC}/depot_tools && \
    cd ${QUIC}/src && ninja -v -C out/Debug quic_client quic_server \
  "
  INSTALL_COMMAND ""
)

add_custom_target(quic-server
  COMMAND ${VAGRANT} ssh -c "\
    pkill quic_server ; \
    /usr/bin/nohup ${BIN}/quic_server --port=6121 \
      --certificate_file=${CERTS}/out/leaf_cert.pem \
      --key_file=${CERTS}/out/leaf_cert.pkcs8 \
      > ${QUIC}/../quic_server.log 2>&1 & \
    sleep 1 \
  "
  DEPENDS proto-quic
  VERBATIM
)

add_custom_target(test-nc
  COMMAND ${NC} -v -D -n -u -w 1 127.0.0.1 6121 < ${CAT} Vagrantfile
  DEPENDS quic-server
)

add_custom_target(test-quickie-client
  COMMAND quickie_client
  DEPENDS quic-server
)

add_custom_target(test
  DEPENDS test-nc test-quickie-client
)
