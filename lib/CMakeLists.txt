string(TOUPPER ${PROJECT_NAME} PROJECT_NAME_UC)
configure_file(include/${PROJECT_NAME}/config.h.in include/${PROJECT_NAME}/config.h)
configure_file(src/config.c.in src/config.c)

string(REGEX REPLACE "/include$" "/bin/openssl" OPENSSL ${OPENSSL_INCLUDE_DIR})
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/src/cert.c
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/src
  COMMAND ${OPENSSL} ecparam -name prime256v1 -out prime256v1.param
  COMMAND
    ${OPENSSL} req -new -newkey ec:prime256v1.param -days 365 -nodes -x509
      -subj "/CN=localhost" -keyout key.pem -noout
  COMMAND echo "#include \"cert.h\"" > cert.c
  COMMAND
    ${OPENSSL} ec -in key.pem -text |
      grep -A1000 priv: | grep -B1000 pub: |
      sed -E -e "s/pub:/};/" -e "s/([0-9a-f][0-9a-f]):?/0x\\1, /g"
             -e "s/priv:/unsigned char tls_key[] = {/"
      >> cert.c
  COMMAND
    ${OPENSSL} ec -in key.pem -text |
      grep -A1000 pub: | grep -B1000 ASN1 | grep -v ASN1 |
      sed -E -e "s/([0-9a-f][0-9a-f]):?/0x\\1, /g"
             -e "s/pub:/unsigned char tls_cert[] = {/"
      >> cert.c
  COMMAND echo "};" >> cert.c
  COMMAND echo "unsigned int tls_key_len = sizeof(tls_key) / sizeof(unsigned char);" >> cert.c
  COMMAND echo "unsigned int tls_cert_len = sizeof(tls_cert) / sizeof(unsigned char);" >> cert.c
  VERBATIM
)

set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/src/cert.c
  PROPERTIES GENERATED True
)

include(GNUInstallDirs)
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)


add_library(common
  OBJECT
    src/fnv_1a.c src/pkt.c src/frame.c src/quic.c src/stream.c src/conn.c
    src/diet.c ${CMAKE_CURRENT_BINARY_DIR}/src/config.c
    ${CMAKE_CURRENT_BINARY_DIR}/src/cert.c
)
add_dependencies(common warpcore ptls-core ptls-minicrypto ptls-openssl)


add_library(${PROJECT_NAME}_stat STATIC $<TARGET_OBJECTS:common>)
add_library(${PROJECT_NAME}_dyn SHARED $<TARGET_OBJECTS:common>)

install(DIRECTORY include/${PROJECT_NAME}
        DESTINATION include
        FILES_MATCHING PATTERN "*.h")

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/include/${PROJECT_NAME}/config.h
        DESTINATION include/${PROJECT_NAME})


set(TARGETS common ${PROJECT_NAME}_stat ${PROJECT_NAME}_dyn)
foreach(TARGET ${TARGETS})
  target_include_directories(${TARGET}
    SYSTEM PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
      $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
      $<INSTALL_INTERFACE:include>
    PRIVATE
      src $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/external/include>
      ${OPENSSL_ROOT_DIR}/include
  )

  set_target_properties(${TARGET}
    PROPERTIES
      POSITION_INDEPENDENT_CODE ON
      INTERPROCEDURAL_OPTIMIZATION True
      OUTPUT_NAME ${PROJECT_NAME}
      VERSION ${PROJECT_VERSION}
      SOVERSION ${PROJECT_VERSION_MAJOR}
      INTERFACE_POSITION_INDEPENDENT_CODE True
  )

  if(NOT ${TARGET} MATCHES "common")
    target_link_libraries(${TARGET}
      warpcore ptls-core ptls-minicrypto ptls-openssl
      ${LIBEV_LIB} Threads::Threads)

    install(TARGETS ${TARGET}
      EXPORT ${TARGET}
      ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
      LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
      RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
  endif()
endforeach()

