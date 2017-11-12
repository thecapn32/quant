string(TOUPPER ${PROJECT_NAME} PROJECT_NAME_UC)
configure_file(include/${PROJECT_NAME}/config.h.in include/${PROJECT_NAME}/config.h)
configure_file(src/config.c.in src/config.c)

set(HOST quant.eggert.org)
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/src/cert.h
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/src
  COMMAND mkdir -p -m 0700 ${HOST}
  COMMAND
    test -d /etc/letsencrypt/live/${HOST} &&
      cp -rL /etc/letsencrypt/live/${HOST} . ||
        scp -r ubuntu@${HOST}:/etc/letsencrypt/live/${HOST} .
  COMMAND echo "#define RSA_CERTIFICATE \\" > cert.h
  COMMAND
    cat ${HOST}/fullchain.pem | sed -e "s/^/    \\\"/" -e "s/$/\\\\n\\\" \\\\/" >> cert.h
  COMMAND echo >> cert.h
  COMMAND echo "#define RSA_PRIVATE_KEY \\" >> cert.h
  COMMAND
    cat ${HOST}/privkey.pem | sed -e "s/^/    \\\"/" -e "s/$/\\\\n\\\" \\\\/" >> cert.h
  VERBATIM
)

set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/src/cert.h
  PROPERTIES GENERATED True
)

include(GNUInstallDirs)

add_library(common
  OBJECT
    src/pkt.c src/frame.c src/quic.c src/stream.c src/conn.c
    src/diet.c src/util.c src/tls.c src/recovery.c
    ${CMAKE_CURRENT_BINARY_DIR}/src/config.c
    ${CMAKE_CURRENT_BINARY_DIR}/src/cert.h
)
add_dependencies(common warpcore ptls-core ptls-openssl)


add_library(${PROJECT_NAME}_stat STATIC $<TARGET_OBJECTS:common>)
add_library(${PROJECT_NAME}_dyn SHARED $<TARGET_OBJECTS:common>)

install(DIRECTORY include/${PROJECT_NAME}
        DESTINATION include
        FILES_MATCHING PATTERN "*.h")

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/include/${PROJECT_NAME}/config.h
        DESTINATION include/${PROJECT_NAME})


find_library(LIBEV_LIB NAMES ev)
if(NOT LIBEV_LIB)
  message(FATAL_ERROR "libev not found")
endif()
find_path(LIBEV_INCLUDE ev.h PATH_SUFFIXES include/ev include)
find_package_handle_standard_args(libev DEFAULT_MSG LIBEV_LIB LIBEV_INCLUDE)
include_directories(${LIBEV_INCLUDE})


if (DSYMUTIL)
  add_custom_command (TARGET ${PROJECT_NAME}_dyn POST_BUILD
    COMMAND ${DSYMUTIL} ARGS *${CMAKE_SHARED_LIBRARY_SUFFIX}
  )
endif()

set(TARGETS common ${PROJECT_NAME}_stat ${PROJECT_NAME}_dyn)
foreach(TARGET ${TARGETS})
  target_include_directories(${TARGET}
    SYSTEM PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
      $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
      $<INSTALL_INTERFACE:include>
    PRIVATE
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
      $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/src>
      $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/external/include>
      ${OPENSSL_ROOT_DIR}/include
  )

  set_target_properties(${TARGET}
    PROPERTIES
      POSITION_INDEPENDENT_CODE ON
      OUTPUT_NAME ${PROJECT_NAME}
      VERSION ${PROJECT_VERSION}
      SOVERSION ${PROJECT_VERSION_MAJOR}
      INTERFACE_POSITION_INDEPENDENT_CODE True
      INTERPROCEDURAL_OPTIMIZATION ${IPO}
  )

  if(NOT ${TARGET} MATCHES "common")
    target_link_libraries(${TARGET}
      warpcore ptls-core ptls-openssl ${LIBEV_LIB})

    install(TARGETS ${TARGET}
      EXPORT ${TARGET}
      ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
      LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
      RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
  endif()
endforeach()

