include(ExternalProject)

externalproject_add(warp
  # UPDATE_COMMAND ""
  GIT_REPOSITORY git@github.com:NTAP/warpcore.git
  CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -DDLEVEL=${DLEVEL}
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DBUILD_DOCUMENTATION=FALSE
  BUILD_BYPRODUCTS
    ${CMAKE_CURRENT_BINARY_DIR}/lib/libsockcore.a
    ${CMAKE_CURRENT_BINARY_DIR}/lib/libwarpcore.a
)

file(MAKE_DIRECTORY
      ${CMAKE_CURRENT_BINARY_DIR}/include ${CMAKE_CURRENT_BINARY_DIR}/lib)
add_library(warpcore STATIC IMPORTED GLOBAL)
set(WARP ${CMAKE_CURRENT_BINARY_DIR}/lib/libwarpcore.a)
if(NOT EXISTS(${WARP}))
  set(WARP ${CMAKE_CURRENT_BINARY_DIR}/lib/libsockcore.a)
endif()
set_target_properties(warpcore PROPERTIES IMPORTED_LOCATION ${WARP})
set_target_properties(warpcore
  PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_BINARY_DIR}/include
)
add_dependencies(warpcore warp)


externalproject_add(picotls
  # UPDATE_COMMAND ""
  GIT_REPOSITORY git@github.com:h2o/picotls.git
  # GIT_TAG kazuho/quic <- this doesn't work, hack around it:
  PATCH_COMMAND git checkout kazuho/quic
  UPDATE_COMMAND "" # <- workaround above causes git error without this
  CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -DOPENSSL_INCLUDE_DIR=/usr/include
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
  INSTALL_COMMAND
    cp -r ${CMAKE_CURRENT_BINARY_DIR}/picotls-prefix/src/picotls/include/
      ${CMAKE_CURRENT_BINARY_DIR}/include &&
    cp ${CMAKE_CURRENT_BINARY_DIR}/picotls-prefix/src/picotls-build/libpicotls-minicrypto.a
      ${CMAKE_CURRENT_BINARY_DIR}/picotls-prefix/src/picotls-build/libpicotls-core.a
      ${CMAKE_CURRENT_BINARY_DIR}/lib
  BUILD_BYPRODUCTS
    ${CMAKE_CURRENT_BINARY_DIR}/lib/libpicotls-minicrypto.a
    ${CMAKE_CURRENT_BINARY_DIR}/lib/libpicotls-core.a
)

add_library(ptls-core STATIC IMPORTED GLOBAL)
set_target_properties(ptls-core
  PROPERTIES IMPORTED_LOCATION
    ${CMAKE_CURRENT_BINARY_DIR}/lib/libpicotls-core.a
)
set_target_properties(ptls-core
  PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_BINARY_DIR}/include
)
add_dependencies(picotls ptls-core)

add_library(ptls-minicrypto STATIC IMPORTED GLOBAL)
set_target_properties(ptls-minicrypto
  PROPERTIES IMPORTED_LOCATION
    ${CMAKE_CURRENT_BINARY_DIR}/lib/libpicotls-minicrypto.a
)
set_target_properties(ptls-minicrypto
  PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_BINARY_DIR}/include
)
add_dependencies(picotls ptls-minicrypto)

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
