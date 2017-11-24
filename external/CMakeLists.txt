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
  externalproject_add(warp
    # UPDATE_COMMAND "" # XXX do not commit with this being empty
    GIT_REPOSITORY https://github.com/NTAP/warpcore.git
    GIT_SHALLOW 1
    GIT_TAG dev
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}
      -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -DDLEVEL=WRN
      -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DBUILD_DOCUMENTATION=FALSE
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
)


externalproject_add(picotls
  # UPDATE_COMMAND "" # XXX do not commit with this being empty
  GIT_REPOSITORY https://github.com/h2o/picotls.git
  GIT_SHALLOW 1
  PATCH_COMMAND sed -i "" -e "s/-std=c99 -Wall -O2 -g//" CMakeLists.txt
  CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    -DOPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}
    -DOPENSSL_LIBRARIES=${OPENSSL_ROOT_DIR}/lib
    -DOPENSSL_INCLUDE_DIR=${OPENSSL_ROOT_DIR}/include
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DCMAKE_POSITION_INDEPENDENT_CODE=True
    -DCMAKE_C_STANDARD=${CMAKE_C_STANDARD}
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
  CONFIGURE_COMMAND ""
  BUILD_IN_SOURCE 1
  INSTALL_COMMAND xcodebuild -alltargets -configuration Debug install
    "HEADER_SEARCH_PATHS=deps/picotls/include include ${OPENSSL_ROOT_DIR}/include"
    LIBRARY_SEARCH_PATHS=${OPENSSL_ROOT_DIR}/lib
    INSTALL_ROOT=${CMAKE_CURRENT_BINARY_DIR}
  BUILD_COMMAND ""
  EXCLUDE_FROM_ALL 1
)


# Use ngtcp2 for testing against
externalproject_add(openssl
  UPDATE_COMMAND ""
  GIT_REPOSITORY https://github.com/openssl/openssl.git
  GIT_SHALLOW 1
  CONFIGURE_COMMAND ./config --prefix=${CMAKE_CURRENT_BINARY_DIR} enable-tls1_3
  BUILD_IN_SOURCE 1
  BUILD_COMMAND make -j16
  INSTALL_COMMAND make install_sw
  EXCLUDE_FROM_ALL 1
)

externalproject_add(ngtcp2
  DEPENDS openssl
  # UPDATE_COMMAND ""
  GIT_REPOSITORY https://github.com/ngtcp2/ngtcp2.git
  GIT_SHALLOW 1
  PATCH_COMMAND autoreconf -i
  CONFIGURE_COMMAND
    ./configure PKG_CONFIG_PATH=${CMAKE_CURRENT_BINARY_DIR}/lib/pkgconfig
      --enable-werror --enable-debug --prefix=${CMAKE_CURRENT_BINARY_DIR}
      --program-prefix=ngtcp2
  BUILD_IN_SOURCE 1
  BUILD_COMMAND make -j16
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
  GIT_TAG NSS_TLS13_DRAFT19_BRANCH
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ./build.sh
  BUILD_IN_SOURCE 1
  INSTALL_COMMAND ""
  EXCLUDE_FROM_ALL 1
)

externalproject_add(mozquic
  DEPENDS nss
  # UPDATE_COMMAND ""
  # GIT_TAG 07
  GIT_REPOSITORY https://github.com/mcmanus/mozquic.git
  GIT_SHALLOW 1
  PATCH_COMMAND sed -i "" -e "s/-Werror//g" Makefile
  CONFIGURE_COMMAND ""
  BUILD_IN_SOURCE 1
  BUILD_COMMAND make -j16
  INSTALL_COMMAND ""
  EXCLUDE_FROM_ALL 1
)


# Use picoquic for testing against
externalproject_add(picoquic
  DEPENDS picotls
  # UPDATE_COMMAND ""
  GIT_REPOSITORY https://github.com/private-octopus/picoquic.git
  GIT_SHALLOW 1
  # PATCH_COMMAND sed -i "" -e "s/-Werror//g" Makefile
  BUILD_IN_SOURCE 1
  CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    -DOPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}
    -DOPENSSL_LIBRARIES=${OPENSSL_ROOT_DIR}/lib
    -DOPENSSL_INCLUDE_DIR=${OPENSSL_ROOT_DIR}/include
    -DPICOTLS_INCLUDE_DIR=${CMAKE_CURRENT_BINARY_DIR}/include
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DCMAKE_POSITION_INDEPENDENT_CODE=True
    -DCMAKE_C_STANDARD=${CMAKE_C_STANDARD}
  EXCLUDE_FROM_ALL 1
  INSTALL_COMMAND ""
)


# Use ats for testing against
externalproject_add(ats
  DEPENDS openssl
  # UPDATE_COMMAND ""
  GIT_REPOSITORY https://github.com/apache/trafficserver.git
  GIT_SHALLOW 1
  GIT_TAG quic-latest
  PATCH_COMMAND autoreconf -i
  CONFIGURE_COMMAND
    ./configure PKG_CONFIG_PATH=${CMAKE_CURRENT_BINARY_DIR}/lib/pkgconfig
      --enable-debug --prefix=${CMAKE_CURRENT_BINARY_DIR}
  BUILD_IN_SOURCE 1
  BUILD_COMMAND make -j16
  EXCLUDE_FROM_ALL 1
)

# grep '^[^#]*_add' ../external/CMakeLists.txt | cut -f2 -d\( | sort | fmt -w 60
add_custom_target(ext-all DEPENDS
                  ats minq mozquic ngtcp2 nspr nss openssl picoquic picotls
                  quicly warp
)
