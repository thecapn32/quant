include(ExternalProject)

externalproject_add(tommyds
  UPDATE_COMMAND ""
  GIT_REPOSITORY https://github.com/amadvance/tommyds.git
  # GIT_TAG 5821a27984ae7c4e0e43eff84c37d58effe06454
  GIT_SHALLOW 1 # not supported in cmake 3.0
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


externalproject_add(warp
  # UPDATE_COMMAND ""
  GIT_REPOSITORY git@github.com:NTAP/warpcore.git
  CMAKE_ARGS -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_CURRENT_BINARY_DIR}
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DBUILD_DOCUMENTATION=FALSE
)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include)
add_library(warpcore STATIC IMPORTED GLOBAL)
set(WARP ${CMAKE_CURRENT_BINARY_DIR}/lib/libwarpcore.a)
if(NOT EXISTS(${WARP}))
  set(WARP ${CMAKE_CURRENT_BINARY_DIR}/lib/libshimcore.a)
endif()
set_target_properties(warpcore PROPERTIES IMPORTED_LOCATION ${WARP})
set_target_properties(warpcore
  PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_BINARY_DIR}/include
)
add_dependencies(warpcore warp)


add_custom_target(vagrant-up ${VAGRANT} up)
add_custom_target(vagrant-down ${VAGRANT} halt)

# location of proto-quic sources inside the VM
string(REPLACE
  ${CMAKE_SOURCE_DIR} /vagrant
  QUIC ${PROJECT_SOURCE_DIR}/external/proto-quic/src/proto-quic)

# some convenience paths under ${QUIC}
set(QUIC_CERTS ${QUIC}/src/net/tools/quic/certs)
set(QUIC_CERTS ${QUIC_CERTS} PARENT_SCOPE)
set(QUIC_BIN ${QUIC}/src/out/Debug)
set(QUIC_BIN ${QUIC_BIN} PARENT_SCOPE)
externalproject_add(proto-quic
  PREFIX ${PROJECT_SOURCE_DIR}/external/proto-quic
  UPDATE_COMMAND ""
  # EXCLUDE_FROM_ALL 1 # not supported in cmake 3.0, see below
  DEPENDS vagrant-up
  GIT_REPOSITORY https://github.com/google/proto-quic.git
  # GIT_TAG 0db5f234b86699c182394bb261ee226ab800b60f
  GIT_SHALLOW 1 # not supported in cmake 3.0
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
    cd ${QUIC}/src && gn gen out/Debug && \
    ninja -v -C out/Debug quic_client quic_server \
  "
  INSTALL_COMMAND ""
)

# EXCLUDE_FROM_ALL workaround for older cmake
set_target_properties(proto-quic PROPERTIES EXCLUDE_FROM_ALL TRUE)

set(QSP quic_server.pid)
string(REPLACE
  ${CMAKE_SOURCE_DIR} /vagrant
  EXTDIR ${PROJECT_SOURCE_DIR})
add_custom_target(quic-server
  COMMAND
    test -f ${PROJECT_SOURCE_DIR}/${QSP} ||
    ${VAGRANT} ssh -c "\
      daemon -F ${EXTDIR}/${QSP} -o ${EXTDIR}/quic_server.log -- \
        ${QUIC_BIN}/quic_server --port=6121 \
        --certificate_file=${QUIC_CERTS}/out/leaf_cert.pem \
        --key_file=${QUIC_CERTS}/out/leaf_cert.pkcs8 --v=9 & \
      sleep 1 \
  " 2> /dev/null
  DEPENDS proto-quic
  VERBATIM
)

add_custom_target(kill-quic-server
  COMMAND
    ${VAGRANT} ssh -c "pkill quic_server" 2> /dev/null &&
    ${RM} -f ${QSP} quic_server.log || true
  DEPENDS vagrant-up
  VERBATIM
)

set(PORT 8443)
add_custom_target(test-${PROJECT_NAME}-server
  COMMAND
    ${RM} -f server.log server.pcap server.core server.profraw || true &&
    ${SUDO} ${PKILL} server sudo || true &&
    ${DAEMON} -e LLVM_PROFILE_FILE=server.profraw -D ${CMAKE_BINARY_DIR}/bin
      -o server.log -- ./server &&
    ${DAEMON} -D ${CMAKE_BINARY_DIR}/bin --
      ${SUDO} ${TCPDUMP} -i lo0 -w server.pcap port ${PORT} &&
    ${VAGRANT} ssh -c "\
      host=`ip route show | grep -i 'default via' | cut -d' ' -f3` ; \
      ${QUIC_BIN}/quic_client --host=$host --port=${PORT} --v=1 \
        http://example.com/ \
    " 2> /dev/null || true &&
    ${SLEEP} 1 &&
    ${SUDO} ${PKILL} server sudo || true &&
    ${CAT} server.log || true
  DEPENDS server vagrant-up
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  VERBATIM
)

add_custom_target(tshark-${PROJECT_NAME}-server-pcap
  COMMAND
    ${TSHARK} -V -2 -n -d udp.port==${PORT},quic -O quic -r server.pcap
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  VERBATIM
)
