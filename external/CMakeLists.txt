include(ExternalProject)

externalproject_add(tommyds
  UPDATE_COMMAND ""
  GIT_REPOSITORY https://github.com/amadvance/tommyds.git
  GIT_TAG 5821a27984ae7c4e0e43eff84c37d58effe06454
  # GIT_SHALLOW 1 # not supported in cmake 3.0
  PATCH_COMMAND ${SED} -i.orig -e "s/-Wpadded// $<SEMICOLON> s/-Wcast-align// \
                  $<SEMICOLON> s/objdump/echo/" Makefile
  CONFIGURE_COMMAND ""
  BUILD_IN_SOURCE 1
  BUILD_COMMAND ${MAKE}
  INSTALL_COMMAND ""
)

externalproject_get_property(tommyds SOURCE_DIR)
add_library(tommy STATIC IMPORTED GLOBAL)
set_target_properties(tommy PROPERTIES IMPORTED_LOCATION ${SOURCE_DIR}/tommy.o)
set_target_properties(tommy
  PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${SOURCE_DIR}
)
add_dependencies(tommy tommyds)


add_custom_target(vagrant-up ${VAGRANT} up)
add_custom_target(vagrant-down ${VAGRANT} halt)

# location of proto-quic sources inside the VM
set(QUIC /vagrant/proto-quic-prefix/src/proto-quic)

# some convenience paths under ${QUIC}
set(QUIC_CERTS ${QUIC}/src/net/tools/quic/certs)
set(QUIC_CERTS ${QUIC_CERTS} PARENT_SCOPE)
set(QUIC_BIN ${QUIC}/src/out/Debug)
set(QUIC_BIN ${QUIC_BIN} PARENT_SCOPE)

externalproject_add(proto-quic
  UPDATE_COMMAND ""
  # EXCLUDE_FROM_ALL 1 # not supported in cmake 3.0, see below
  DEPENDS vagrant-up
  GIT_REPOSITORY https://github.com/google/proto-quic.git
  GIT_TAG 17db47fb4265d45430ca5a3b4180ed52dfedf817
  # GIT_SHALLOW 1 # not supported in cmake 3.0
  CONFIGURE_COMMAND ${VAGRANT} ssh -c "\
    echo ttf-mscorefonts-installer msttcorefonts/accepted-mscorefonts-eula \
      select true | sudo debconf-set-selections && \
    export PATH=$PATH:${QUIC}/depot_tools && \
    ${QUIC}/src/build/install-build-deps.sh --no-syms --no-arm \
      --no-chromeos-fonts --no-nacl --no-prompt && \
    ${QUIC}/src/third_party/binutils/download.py && \
    cd ${QUIC_CERTS} && ./generate-certs.sh \
  "
  BUILD_IN_SOURCE 1
  BUILD_COMMAND ${VAGRANT} ssh -c "\
    export PATH=$PATH:${QUIC}/depot_tools && \
    cd ${QUIC}/src && gn gen out/Debug && ninja -v -C out/Debug quic_client quic_server \
  "
  INSTALL_COMMAND ""
)

# EXCLUDE_FROM_ALL workaround for older cmake
set_target_properties(proto-quic PROPERTIES EXCLUDE_FROM_ALL TRUE)

add_custom_target(quic-server
  COMMAND
    ${VAGRANT} ssh -c "\
      pkill quic_server ; \
      /usr/bin/nohup ${QUIC_BIN}/quic_server --port=6121 \
        --certificate_file=${QUIC_CERTS}/out/leaf_cert.pem \
        --key_file=${QUIC_CERTS}/out/leaf_cert.pkcs8 \
        > /vagrant/quic_server.log 2>&1 & \
      sleep 1 \
  "
  DEPENDS proto-quic
  VERBATIM
)

add_custom_target(kill-quic-server
  COMMAND ${VAGRANT} ssh -c "pkill quic_server"
  DEPENDS vagrant-up
  VERBATIM
)

set(DIR ${CMAKE_BINARY_DIR}/bin)
set(QS quickie_server)
set(PORT 8443)
add_custom_target(test-quickie-server
  COMMAND
    ${RM} ${DIR}/${QS}.log || true &&
    ${SUDO} ${PKILL} ${QS} sudo || true &&
    ${DAEMON} -e LLVM_PROFILE_FILE=${QS}.profraw -D ${DIR} -E ${DIR}/${QS}.log
      ${DIR}/${QS} &&
    ${DAEMON} ${SUDO} ${TCPDUMP} -i lo0 -w ${DIR}/${QS}.pcap port ${PORT} &&
    ${VAGRANT} ssh -c "\
      host=`ip route show | grep -i 'default via' | cut -d' ' -f3` ; \
      ${QUIC_BIN}/quic_client --host=$host --port=${PORT} http://example.com/ \
    " || true &&
    ${SUDO} ${PKILL} ${QS} sudo || true &&
    ${CAT} ${DIR}/${QS}.log || true &&
    ${TSHARK} -V -2 -n -d udp.port==${PORT},quic -R frame.number==1
      -O quic -r ${DIR}/${QS}.pcap
  DEPENDS quickie_server vagrant-up
  VERBATIM
)
