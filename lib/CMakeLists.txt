string(TOUPPER ${PROJECT_NAME} PROJECT_NAME_UC)
configure_file(include/${PROJECT_NAME}/config.h.in include/${PROJECT_NAME}/config.h)
configure_file(src/config.c.in src/config.c)

find_program(XXD xxd)
if(NOT XXD)
  message(FATAL_ERROR "xxd not found")
endif()

string(REGEX REPLACE "/include$" "/bin/openssl" OPENSSL ${OPENSSL_INCLUDE_DIR})
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/src/cert.c
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/src
  COMMAND ${OPENSSL} ecparam -name prime256v1 -out prime256v1.param
  COMMAND
    ${OPENSSL} req -new -newkey ec:prime256v1.param -days 365 -nodes -x509
      -subj "/CN=localhost" -keyout key.pem -out cert.pem
  COMMAND ${OPENSSL} enc -base64 -d -in key.pem -out tls.key
  COMMAND ${OPENSSL} enc -base64 -d -in cert.pem -out tls.cert
  COMMAND echo "#include \"cert.h\"" > cert.c
  COMMAND ${XXD} -i tls.key >> cert.c
  COMMAND ${XXD} -i tls.cert >> cert.c
  VERBATIM
)

set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/src/cert.c
  PROPERTIES GENERATED True
)

include(GNUInstallDirs)
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

set(${PROJECT_NAME}_sources
  src/fnv_1a.c src/pkt.c src/frame.c src/quic.c src/stream.c src/conn.c
  src/diet.c ${CMAKE_CURRENT_BINARY_DIR}/src/config.c
  ${CMAKE_CURRENT_BINARY_DIR}/src/cert.c
)

add_library(${PROJECT_NAME}_static STATIC ${${PROJECT_NAME}_sources})

set_target_properties(${PROJECT_NAME}_static
  PROPERTIES
    POSITION_INDEPENDENT_CODE ON
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
    POSITION_INDEPENDENT_CODE ON
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
  warpcore ptls-core ptls-minicrypto ptls-openssl
  ${LIBEV_LIB} Threads::Threads)

target_link_libraries(${PROJECT_NAME}
  warpcore ptls-core ptls-minicrypto ptls-openssl
  ${LIBEV_LIB} Threads::Threads)
