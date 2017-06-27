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
  # GIT_TAG kazuho/quic
  GIT_SHALLOW 1
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
)

# EXCLUDE_FROM_ALL workaround for older cmake
set_target_properties(quic-go PROPERTIES EXCLUDE_FROM_ALL TRUE)

add_custom_target(go-client
                  DEPENDS quic-go
                  COMMAND ${GOPATH}/bin/client -v https://127.0.0.1:8443/)

add_custom_target(go-server
                  DEPENDS quic-go
                  COMMAND ${GOPATH}/bin/example -v -bind 127.0.0.1:8443)
