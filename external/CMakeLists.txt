include(externalproject)

foreach(PROG daemonize pkill tcpdump tshark sed make)
  string(TOUPPER ${PROG} VARNAME)
  find_program(${VARNAME} ${PROG})
  if(NOT ${VARNAME})
    message(FATAL_ERROR "${PROG} not found; please install it")
  endif()
endforeach()

# find_program() for sudo is unlikely to work, hence the special case; see
# https://cmake.org/pipermail/cmake/2010-September/039520.html
find_program(SUDO sudo)
if(NOT SUDO)
  set(SUDO /usr/bin/sudo)
endif()

externalproject_add(tommyds
  UPDATE_COMMAND ""
  GIT_REPOSITORY https://github.com/amadvance/tommyds.git
  GIT_SHALLOW 1
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
  EXCLUDE_FROM_ALL 1
  DEPENDS vagrant-up
  GIT_REPOSITORY https://github.com/google/proto-quic.git
  GIT_SHALLOW 1
  CONFIGURE_COMMAND ${VAGRANT} ssh -c "\
    echo ttf-mscorefonts-installer msttcorefonts/accepted-mscorefonts-eula \
      select true | sudo debconf-set-selections && \
    ${QUIC}/src/build/install-build-deps.sh --no-syms --no-arm \
      --no-chromeos-fonts --no-nacl --no-prompt && \
    export PATH=$PATH:${QUIC}/depot_tools && \
    cd ${QUIC}/src && gclient runhooks && \
    cd ${QUIC_CERTS} && ./generate-certs.sh \
  "
  BUILD_IN_SOURCE 1
  BUILD_COMMAND ${VAGRANT} ssh -c "\
    export PATH=$PATH:${QUIC}/depot_tools && \
    cd ${QUIC}/src && ninja -v -C out/Debug quic_client quic_server \
  "
  INSTALL_COMMAND ""
)

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

set(DIR ${CMAKE_BINARY_DIR}/test)
set(QS quickie_server)
set(PORT 8443)
add_custom_target(test-quickie-server
  COMMAND
    ${SUDO} ${PKILL} ${QS} sudo || true &&
    ${DAEMONIZE} -e ${DIR}/${QS}.log ${DIR}/${QS} &&
    ${DAEMONIZE} ${SUDO} ${TCPDUMP} -i lo0 -w ${DIR}/${QS}.pcap port ${PORT} &&
    ${VAGRANT} ssh -c "\
      host=`ip route show | grep -i 'default via' | cut -d' ' -f3` ; \
      ${QUIC_BIN}/quic_client --host=$host --port=${PORT} http://example.com/ \
    " || true &&
    ${SUDO} ${PKILL} ${QS} sudo || true &&
    ${CAT} ${DIR}/${QS}.log &&
    ${TSHARK} -V -2 -n -d udp.port==${PORT},quic -R frame.number==1
      -r ${DIR}/${QS}.pcap
  DEPENDS quickie_server vagrant-up
  VERBATIM
)
