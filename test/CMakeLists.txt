find_program(VAGRANT vagrant)
find_program(NC nc)

add_custom_target(vagrant-up ${VAGRANT} up)

# https://github.com/google/proto-quic will be checked out here
set(QUIC /vagrant/proto-quic)

# some convenience paths under ${QUIC}
set(CERTS ${QUIC}/src/net/tools/quic/certs)
set(BIN ${QUIC}/src/out/Debug)

include(ExternalProject)
externalproject_add(proto-quic
  EXCLUDE_FROM_ALL 1
  DEPENDS vagrant-up
  GIT_REPOSITORY https://github.com/google/proto-quic.git
  PREFIX proto-quic
  # UPDATE_DISCONNECTED 1
  # CONFIGURE_COMMAND ""
  CONFIGURE_COMMAND ${VAGRANT} ssh -c "\
    echo ttf-mscorefonts-installer msttcorefonts/accepted-mscorefonts-eula \
      select true | sudo debconf-set-selections && \
    ${QUIC}/src/build/install-build-deps.sh --no-syms --no-arm \
      --no-chromeos-fonts --no-nacl --no-prompt && \
    export PATH=$PATH:${QUIC}/depot_tools && \
    cd ${QUIC}/src && \
    gclient runhooks"
  BUILD_COMMAND ${VAGRANT} ssh -c "\
    export PATH=$PATH:${QUIC}/depot_tools && \
    cd ${QUIC}/src && \
    ninja -v -C out/Debug quic_client quic_server && \
    cd ${CERTS} && \
    ./generate-certs.sh"
  INSTALL_COMMAND ""
)

add_test(vagrant-up ${VAGRANT} up)

add_test(quic ${VAGRANT} ssh -c "\
           (nohup ${BIN}/quic_server --port=6121 \
              --certificate_file=${CERTS}/out/leaf_cert.pem \
              --key_file=${CERTS}/out/leaf_cert.pkcs8 \
              > ${QUIC}/../quic_server.log 2>&1 &) ; sleep 3 ; \
            ps -ef | grep quic_server \
")
set_tests_properties(quic PROPERTIES DEPENDS vagrant-up)

add_test(nc ${NC} -v -D -n -u -w 1 127.0.0.1 6121 < cat Vagrantfile)
set_tests_properties(nc PROPERTIES DEPENDS quic)

add_test(kill-quic ${VAGRANT} ssh -c "pkill quic_server")
set_tests_properties(kill-quic PROPERTIES DEPENDS nc)
