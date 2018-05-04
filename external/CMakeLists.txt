include(ExternalProject)

if(BUILD_SHARED_LIBS)
  set(CMAKE_FIND_LIBRARY_PREFIXES ${CMAKE_SHARED_LIBRARY_PREFIX})
  set(CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_SHARED_LIBRARY_SUFFIX})
  set(LIBRARY_PREFIX ${CMAKE_SHARED_LIBRARY_PREFIX})
  set(LIBRARY_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
else()
  set(CMAKE_FIND_LIBRARY_PREFIXES ${CMAKE_STATIC_LIBRARY_PREFIX})
  set(CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_STATIC_LIBRARY_SUFFIX})
  set(LIBRARY_PREFIX ${CMAKE_STATIC_LIBRARY_PREFIX})
  set(LIBRARY_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
endif()


if(NOT WARP_LIB OR NOT WARP_INCLUDE)
  # fix for https://github.com/NTAP/quant/issues/7
  file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include)

  if(NO_SANITIZERS)
    set(NO_SANITIZERS_FLAGS "-DNO_SANITIZERS=True")
  endif()

  externalproject_add(warp
    # UPDATE_COMMAND "" # XXX do not commit with this being empty
    GIT_REPOSITORY https://github.com/NTAP/warpcore.git
    GIT_SHALLOW 1
    GIT_TAG dev
    CMAKE_ARGS
      -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}
      -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
      -DDLEVEL=WRN
      -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
      -DBUILD_DOCUMENTATION=FALSE
      ${NO_SANITIZERS_FLAGS}
    BUILD_BYPRODUCTS
      ${CMAKE_CURRENT_BINARY_DIR}/lib/${LIBRARY_PREFIX}warpcore${LIBRARY_SUFFIX}
      ${CMAKE_CURRENT_BINARY_DIR}/lib/${LIBRARY_PREFIX}sockcore${LIBRARY_SUFFIX}
  )
  add_dependencies(warpcore warp)
  set(WARP_LIB ${CMAKE_CURRENT_BINARY_DIR}/lib/${LIBRARY_PREFIX}warpcore${LIBRARY_SUFFIX})
  if(NOT EXISTS ${WARP_LIB})
    set(WARP_LIB ${CMAKE_CURRENT_BINARY_DIR}/lib/${LIBRARY_PREFIX}sockcore${LIBRARY_SUFFIX})
  endif()
  set(WARP_INCLUDE ${CMAKE_CURRENT_BINARY_DIR}/include)
endif()

set_target_properties(warpcore PROPERTIES
  IMPORTED_LOCATION ${WARP_LIB}
  INTERFACE_INCLUDE_DIRECTORIES ${WARP_INCLUDE}
  INTERFACE_LINK_LIBRARIES dl
)


externalproject_add(picotls
  # UPDATE_COMMAND "" # XXX do not commit with this being empty
  GIT_REPOSITORY https://github.com/h2o/picotls.git
  GIT_SHALLOW 1
  GIT_TAG 914fc78b9f88ca5e15aefeeff239e7e5c2d608c4
  CMAKE_ARGS
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    -DOPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
  INSTALL_COMMAND
    cp -a ${CMAKE_CURRENT_BINARY_DIR}/picotls-prefix/src/picotls/include
      ${CMAKE_CURRENT_BINARY_DIR} &&
    cp -a ${CMAKE_CURRENT_BINARY_DIR}/picotls-prefix/src/picotls-build/${LIBRARY_PREFIX}picotls-minicrypto${LIBRARY_SUFFIX}
      ${CMAKE_CURRENT_BINARY_DIR}/picotls-prefix/src/picotls-build/${LIBRARY_PREFIX}picotls-openssl${LIBRARY_SUFFIX}
      ${CMAKE_CURRENT_BINARY_DIR}/picotls-prefix/src/picotls-build/${LIBRARY_PREFIX}picotls-core${LIBRARY_SUFFIX}
      ${CMAKE_CURRENT_BINARY_DIR}/lib || true
  BUILD_BYPRODUCTS
    ${CMAKE_CURRENT_BINARY_DIR}/lib/${LIBRARY_PREFIX}picotls-minicrypto${LIBRARY_SUFFIX}
    ${CMAKE_CURRENT_BINARY_DIR}/lib/${LIBRARY_PREFIX}picotls-openssl${LIBRARY_SUFFIX}
    ${CMAKE_CURRENT_BINARY_DIR}/lib/${LIBRARY_PREFIX}picotls-core${LIBRARY_SUFFIX}
)

foreach(TARGET ptls-core ptls-minicrypto ptls-openssl)
  add_library(${TARGET} STATIC IMPORTED GLOBAL)
  string(REGEX REPLACE "ptls" "picotls" LIBNAME ${TARGET})
  set_target_properties(${TARGET}
    PROPERTIES
      IMPORTED_LOCATION
        ${CMAKE_CURRENT_BINARY_DIR}/lib/${LIBRARY_PREFIX}${LIBNAME}${LIBRARY_SUFFIX}
      INTERFACE_INCLUDE_DIRECTORIES
        "${CMAKE_CURRENT_BINARY_DIR}/include;${OPENSSL_ROOT_DIR}/include"
      INTERFACE_LINK_LIBRARIES "${OPENSSL_LIBRARIES}"
      INTERFACE_POSITION_INDEPENDENT_CODE True
  )
  add_dependencies(${TARGET} picotls)
endforeach()


set(GOPATH ${CMAKE_CURRENT_BINARY_DIR}/go)

# # Use quic-go for testing against, rather than proto-quic monster
# set(QUICGO github.com/lucas-clemente/quic-go)
# externalproject_add(quic-go
#   DOWNLOAD_COMMAND env GOPATH=${GOPATH} go get ${QUICGO}
#   CONFIGURE_COMMAND ""
#   BUILD_COMMAND
#     cd ${GOPATH}/src/${QUICGO} && env GOPATH=${GOPATH} go get -t -u ./...
#   INSTALL_COMMAND ""
#   EXCLUDE_FROM_ALL 1
# )


# Use minq for testing against
set(MINQ github.com/ekr/minq)
set(MINQDEPS github.com/bifurcation/mint github.com/cloudflare/cfssl/helpers)
externalproject_add(minq
  DOWNLOAD_COMMAND env GOPATH=${GOPATH} go get ${MINQ} ${MINQDEPS}
  UPDATE_COMMAND ""
  # UPDATE_COMMAND env GOPATH=${GOPATH} go get -u ${MINQ} ${MINQDEPS}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND cd ${GOPATH}/src/${MINQ} && env GOPATH=${GOPATH} go test
  INSTALL_COMMAND ""
  EXCLUDE_FROM_ALL 1
)


# Use quicly for testing against
externalproject_add(quicly
  # UPDATE_COMMAND ""
  GIT_REPOSITORY https://github.com/h2o/quicly.git
  GIT_SHALLOW 1
  CMAKE_ARGS
    -DOPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
  INSTALL_COMMAND ""
  EXCLUDE_FROM_ALL 1
)


# Use ngtcp2 for testing against
externalproject_add(openssl
  UPDATE_COMMAND ""
  # GIT_REPOSITORY https://github.com/openssl/openssl.git
  GIT_REPOSITORY https://github.com/tatsuhiro-t/openssl
  GIT_TAG tlsv1.3-28
  GIT_SHALLOW 1
  CONFIGURE_COMMAND ./config --prefix=${CMAKE_CURRENT_BINARY_DIR} enable-tls1_3
  BUILD_IN_SOURCE 1
  BUILD_COMMAND make -j8
  INSTALL_COMMAND make install_sw
  EXCLUDE_FROM_ALL 1
)

externalproject_add(ngtcp2
  DEPENDS openssl
  UPDATE_COMMAND ""
  GIT_REPOSITORY https://github.com/ngtcp2/ngtcp2.git
  GIT_SHALLOW 1
  PATCH_COMMAND autoreconf -i
  CONFIGURE_COMMAND
    ./configure PKG_CONFIG_PATH=${CMAKE_CURRENT_BINARY_DIR}/lib/pkgconfig
      --enable-werror --enable-debug --prefix=${CMAKE_CURRENT_BINARY_DIR}
      --program-prefix=ngtcp2
  BUILD_IN_SOURCE 1
  BUILD_COMMAND make -j8
  EXCLUDE_FROM_ALL 1
)


# Use mozquic for testing against
externalproject_add(nspr
  UPDATE_COMMAND ""
  SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/mozquic-prefix/src/nspr
  CONFIGURE_COMMAND ""
  HG_REPOSITORY https://hg.mozilla.org/projects/nspr
  BUILD_COMMAND ""
  INSTALL_COMMAND ""
  EXCLUDE_FROM_ALL 1
)

externalproject_add(nss
  DEPENDS nspr
  UPDATE_COMMAND ""
  SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/mozquic-prefix/src/nss
  GIT_REPOSITORY https://github.com/nss-dev/nss.git
  GIT_SHALLOW 1
  GIT_TAG origin/NSS_3_36_BRANCH
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make nss_build_all USE_64=1
  BUILD_IN_SOURCE 1
  INSTALL_COMMAND ""
  EXCLUDE_FROM_ALL 1
)

externalproject_add(mozquic
  DEPENDS nss
  # UPDATE_COMMAND ""
  GIT_REPOSITORY https://github.com/mcmanus/mozquic.git
  GIT_SHALLOW 1
  PATCH_COMMAND sed -i "" -e "s/-Werror//g $<SEMICOLON> s|include/nspr|include|g" Makefile
  CONFIGURE_COMMAND ""
  BUILD_IN_SOURCE 1
  BUILD_COMMAND make -j8
  INSTALL_COMMAND ""
  EXCLUDE_FROM_ALL 1
)


# Use picoquic for testing against
externalproject_add(picoquic
  DEPENDS picotls
  # UPDATE_COMMAND ""
  GIT_REPOSITORY https://github.com/private-octopus/picoquic.git
  GIT_SHALLOW 1
  # GIT_TAG draft-21
  BUILD_IN_SOURCE 1
  CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    -DOPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}
    -DPICOTLS_INCLUDE_DIR=${CMAKE_CURRENT_BINARY_DIR}/include
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
  INSTALL_COMMAND ""
  EXCLUDE_FROM_ALL 1
)


# Use ats for testing against
externalproject_add(ats
  DEPENDS openssl
  UPDATE_COMMAND ""
  GIT_REPOSITORY https://github.com/apache/trafficserver.git
  GIT_SHALLOW 1
  GIT_TAG quic-latest
  PATCH_COMMAND autoreconf -i
  CONFIGURE_COMMAND
    ./configure PKG_CONFIG_PATH=${CMAKE_CURRENT_BINARY_DIR}/lib/pkgconfig
      --enable-debug --prefix=${CMAKE_CURRENT_BINARY_DIR}
  BUILD_IN_SOURCE 1
  BUILD_COMMAND make -j8
  INSTALL_COMMAND
    make install &&
    echo "CONFIG proxy.config.udp.threads INT 1" >> ${CMAKE_CURRENT_BINARY_DIR}/etc/trafficserver/records.config &&
    echo "CONFIG proxy.config.quic.no_activity_timeout_in INT 10" >> ${CMAKE_CURRENT_BINARY_DIR}/etc/trafficserver/records.config &&
    sed -i "" -E
      -e "s/.*proxy.config.diags.debug.enabled.*/CONFIG proxy.config.diags.debug.enabled INT 1/g"
      -e "s/.*proxy.config.diags.debug.tags.*/CONFIG proxy.config.diags.debug.tags STRING quic|udp/g"
      -e "s/.*proxy.config.http.server_ports.*/CONFIG proxy.config.http.server_ports STRING 4433:quic/g"
      -e "s/.*proxy.config.ssl.server.cipher_suite.*/CONFIG proxy.config.ssl.server.cipher_suite STRING TLS13-AES-128-GCM-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-CHACHA20-POLY1305-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-DSS-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA/g"
      ${CMAKE_CURRENT_BINARY_DIR}/etc/trafficserver/records.config
  EXCLUDE_FROM_ALL 1
)


# Use quicker for testing against
externalproject_add(node
  UPDATE_COMMAND ""
  GIT_REPOSITORY https://github.com/kevin-kp/node
  GIT_SHALLOW 1
  GIT_TAG add_quicker_support-tls-d28
  BUILD_IN_SOURCE 1
  CONFIGURE_COMMAND
    ./configure --openssl-no-asm --prefix=${CMAKE_CURRENT_BINARY_DIR}
  BUILD_COMMAND make -j8
  EXCLUDE_FROM_ALL 1
)

externalproject_add(quicker
  DEPENDS node
  UPDATE_COMMAND ""
  GIT_REPOSITORY https://github.com/rmarx/quicker
  GIT_SHALLOW 1
  PATCH_COMMAND
    npm install &&
    npm install typescript &&
    node_modules/typescript/bin/tsc -p .
  CONFIGURE_COMMAND ""
  BUILD_IN_SOURCE 1
  BUILD_COMMAND ""
  INSTALL_COMMAND ""
  EXCLUDE_FROM_ALL 1
)


# grep '^[^#]*_add' ../external/CMakeLists.txt | cut -f2 -d\( | sort | fmt -w 60
add_custom_target(ext-all DEPENDS
  ats minq mozquic ngtcp2 node nspr nss openssl picoquic
  picotls quicker quicly warp
)
