include(ExternalProject)

externalproject_add(warp
  UPDATE_COMMAND ""
  GIT_REPOSITORY https://github.com/NTAP/warpcore.git
  GIT_SHALLOW 1
  CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -DDLEVEL=${DLEVEL}
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DBUILD_DOCUMENTATION=FALSE
  BUILD_BYPRODUCTS
    ${CMAKE_CURRENT_BINARY_DIR}/lib/libsockcore.a
    # ${CMAKE_CURRENT_BINARY_DIR}/lib/libwarpcore.a
)

file(MAKE_DIRECTORY
      ${CMAKE_CURRENT_BINARY_DIR}/include ${CMAKE_CURRENT_BINARY_DIR}/lib)
add_library(warpcore STATIC IMPORTED GLOBAL)
set(WARP ${CMAKE_CURRENT_BINARY_DIR}/lib/libwarpcore.a)
if(NOT EXISTS(${WARP}))
  set(WARP ${CMAKE_CURRENT_BINARY_DIR}/lib/libsockcore.a)
endif()
set_target_properties(warpcore PROPERTIES
  IMPORTED_LOCATION ${WARP}
  INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_BINARY_DIR}/include
)
add_dependencies(warpcore warp)


# build picotls with our CFLAGS, but without -Werror
string(TOUPPER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE_UC)
set(PICOTLS_CFLAGS "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UC}}")
string(REPLACE "-Werror" "" PICOTLS_CFLAGS "${PICOTLS_CFLAGS}")
string(REPLACE "-Wextra" "" PICOTLS_CFLAGS "${PICOTLS_CFLAGS}")
string(REPLACE "-Wpedantic" "" PICOTLS_CFLAGS "${PICOTLS_CFLAGS}")
string(REPLACE "-Weverything" "" PICOTLS_CFLAGS "${PICOTLS_CFLAGS}")
string(REPLACE "-fsanitize=leak" "" PICOTLS_CFLAGS "${PICOTLS_CFLAGS}")
string(REPLACE "-fsanitize=undefined" "" PICOTLS_CFLAGS "${PICOTLS_CFLAGS}")

externalproject_add(picotls
  UPDATE_COMMAND ""
  GIT_REPOSITORY https://github.com/h2o/picotls.git
  GIT_SHALLOW 1
  GIT_TAG kazuho/draft21
  PATCH_COMMAND sed -i "" -e "s/-std=c99 -Wall -O2 -g//" CMakeLists.txt
  CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    -DCMAKE_C_FLAGS=${PICOTLS_CFLAGS}
    -DOPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}
    -DOPENSSL_LIBRARIES=${OPENSSL_ROOT_DIR}/lib
    -DOPENSSL_INCLUDE_DIR=${OPENSSL_ROOT_DIR}/include
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DCMAKE_POSITION_INDEPENDENT_CODE=True
  INSTALL_COMMAND
    cp -a ${CMAKE_CURRENT_BINARY_DIR}/picotls-prefix/src/picotls/include
      ${CMAKE_CURRENT_BINARY_DIR} &&
    cp -a ${CMAKE_CURRENT_BINARY_DIR}/picotls-prefix/src/picotls-build/libpicotls-minicrypto.a
      ${CMAKE_CURRENT_BINARY_DIR}/picotls-prefix/src/picotls-build/libpicotls-openssl.a
      ${CMAKE_CURRENT_BINARY_DIR}/picotls-prefix/src/picotls-build/libpicotls-core.a
      ${CMAKE_CURRENT_BINARY_DIR}/lib || true
  BUILD_BYPRODUCTS
    ${CMAKE_CURRENT_BINARY_DIR}/lib/libpicotls-minicrypto.a
    ${CMAKE_CURRENT_BINARY_DIR}/lib/libpicotls-openssl.a
    ${CMAKE_CURRENT_BINARY_DIR}/lib/libpicotls-core.a
)

foreach(TARGET ptls-core ptls-minicrypto ptls-openssl)
  add_library(${TARGET} STATIC IMPORTED GLOBAL)
  string(REGEX REPLACE "ptls" "picotls" LIBNAME ${TARGET})
  set_target_properties(${TARGET}
    PROPERTIES
      IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/lib/lib${LIBNAME}.a
      INTERFACE_INCLUDE_DIRECTORIES
        "${CMAKE_CURRENT_BINARY_DIR}/include;${OPENSSL_ROOT_DIR}/include"
      INTERFACE_LINK_LIBRARIES "${OPENSSL_LIBRARIES}"
      INTERFACE_POSITION_INDEPENDENT_CODE True
  )
  add_dependencies(${TARGET} picotls)
endforeach()


# Use quic-go for testing against, rather than proto-quic monster
set(GOPATH ${CMAKE_CURRENT_BINARY_DIR}/go)
set(QUICGO github.com/lucas-clemente/quic-go)
externalproject_add(quic-go
  DOWNLOAD_COMMAND env GOPATH=${GOPATH} go get ${QUICGO}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND
    cd ${GOPATH}/src/${QUICGO} && env GOPATH=${GOPATH} go get -t -u ./...
  INSTALL_COMMAND ""
  EXCLUDE_FROM_ALL 1
)


# Use minq for testing against
set(MINQ github.com/ekr/minq)
externalproject_add(minq
  DOWNLOAD_COMMAND
    env GOPATH=${GOPATH} go get ${MINQ} &&
      env GOPATH=${GOPATH} go get github.com/cloudflare/cfssl/helpers || true
  UPDATE_COMMAND cd ${GOPATH}/src/github.com/ekr/minq && git pull
  CONFIGURE_COMMAND
    cd ${GOPATH}/src/github.com/bifurcation/mint &&
      git remote add ekr https://www.github.com/ekr/mint || true &&
      git fetch ekr && git checkout minq_draft_21
  BUILD_COMMAND
    cd ${GOPATH}/src/${MINQ} && env GOPATH=${GOPATH} go test
  INSTALL_COMMAND ""
  EXCLUDE_FROM_ALL 1
)


# Use quicly for testing against
externalproject_add(quicly
  UPDATE_COMMAND ""
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
  CONFIGURE_COMMAND ./config --prefix=${CMAKE_BINARY_DIR} enable-tls1_3
  BUILD_IN_SOURCE 1
  INSTALL_COMMAND make install_sw
  BUILD_COMMAND make -j16
  EXCLUDE_FROM_ALL 1
)

externalproject_add(ngtcp2
  DEPENDS openssl
  UPDATE_COMMAND ""
  GIT_REPOSITORY https://github.com/ngtcp2/ngtcp2.git
  GIT_SHALLOW 1
  PATCH_COMMAND autoreconf -i
  CONFIGURE_COMMAND
    env CFLAGS=-I${CMAKE_BINARY_DIR}/include
      CXXFLAGS=-I${CMAKE_BINARY_DIR}/include
      ./configure --enable-werror --enable-debug --prefix=${CMAKE_BINARY_DIR}
        --program-prefix=ngtcp2
  BUILD_IN_SOURCE 1
  BUILD_COMMAND make -j16
  EXCLUDE_FROM_ALL 1
)


# Use mozquic for testing against
externalproject_add(nspr
  UPDATE_COMMAND ""
  SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/nss-prefix/src/nspr
  CONFIGURE_COMMAND ""
  HG_REPOSITORY https://hg.mozilla.org/projects/nspr
  BUILD_COMMAND ""
  INSTALL_COMMAND ""
  EXCLUDE_FROM_ALL 1
)

externalproject_add(nss
  DEPENDS nspr
  UPDATE_COMMAND ""
  GIT_REPOSITORY https://github.com/nss-dev/nss.git
  GIT_SHALLOW 1
  GIT_TAG NSS_TLS13_DRAFT19_BRANCH
  CONFIGURE_COMMAND ""
  BUILD_COMMAND env USE_64=1 make nss_build_all
  BUILD_IN_SOURCE 1
  INSTALL_COMMAND env USE_64=1 make install
  EXCLUDE_FROM_ALL 1
)

externalproject_add(mozquic
  DEPENDS nss
  UPDATE_COMMAND ""
  GIT_REPOSITORY https://github.com/mcmanus/mozquic.git
  GIT_SHALLOW 1
  CONFIGURE_COMMAND ""
  BUILD_IN_SOURCE 1
  BUILD_COMMAND
    env NSS_ROOT=${CMAKE_CURRENT_BINARY_DIR}/nss-prefix/src/nss make
  INSTALL_COMMAND ""
  EXCLUDE_FROM_ALL 1
)
