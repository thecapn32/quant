string(TOUPPER ${PROJECT_NAME} PROJECT_NAME_UC)
configure_file(include/${PROJECT_NAME}/config.h.in include/${PROJECT_NAME}/config.h)
configure_file(src/config.c.in src/config.c)

add_custom_command(
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/src
  COMMAND openssl ecparam -name prime256v1 -out prime256v1.param
  COMMAND
    openssl req -new -newkey ec:prime256v1.param -days 365 -nodes -x509
      -subj "/CN=localhost" -keyout key.pem -out cert.pem
  COMMAND grep -v "EC PRIVATE KEY" key.pem | base64 -D > tls.key
  COMMAND grep -v "CERTIFICATE" cert.pem | base64 -D > tls.cert
  COMMAND echo "#include \"cert.h\"" > cert.c
  COMMAND xxd -i tls.key >> cert.c
  COMMAND xxd -i tls.cert >> cert.c
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/src/cert.c
  VERBATIM
)

include(GNUInstallDirs)
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

set(${PROJECT_NAME}_sources
  src/fnv_1a.c src/pkt.c src/frame.c src/quic.c src/stream.c src/conn.c
  ${CMAKE_CURRENT_BINARY_DIR}/src/config.c
  ${CMAKE_CURRENT_BINARY_DIR}/src/cert.c
)

add_library(${PROJECT_NAME}_static STATIC ${${PROJECT_NAME}_sources})

set_target_properties(${PROJECT_NAME}_static
  PROPERTIES
    INTERPROCEDURAL_OPTIMIZATION True
    OUTPUT_NAME ${PROJECT_NAME}
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

target_include_directories(${PROJECT_NAME}_static
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE src external/include
)

install(TARGETS ${PROJECT_NAME}_static
  EXPORT ${PROJECT_NAME}_static_config
  ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR}
)

add_library(${PROJECT_NAME} SHARED ${${PROJECT_NAME}_sources})

set_target_properties(${PROJECT_NAME}
  PROPERTIES
    INTERPROCEDURAL_OPTIMIZATION True
    OUTPUT_NAME ${PROJECT_NAME}
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

target_include_directories(${PROJECT_NAME}
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE src external/include
)

install(TARGETS ${PROJECT_NAME}
  EXPORT ${PROJECT_NAME}_config
  ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY include/${PROJECT_NAME}
        DESTINATION include
        FILES_MATCHING PATTERN "*.h")

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/include/${PROJECT_NAME}/config.h
        DESTINATION include/${PROJECT_NAME})

target_link_libraries(${PROJECT_NAME}_static
  warpcore ptls-core ptls-minicrypto ${LIBEV_LIB} Threads::Threads)

target_link_libraries(${PROJECT_NAME}
  warpcore ptls-core ptls-minicrypto ${LIBEV_LIB} Threads::Threads)
