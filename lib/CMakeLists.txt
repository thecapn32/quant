# Get the latest commit hash of the working branch
execute_process(
  COMMAND git log -1 --format=%H
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_COMMIT_HASH_STR
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(REGEX REPLACE "^(..)" "0x\\1, " GIT_COMMIT_HASH "${GIT_COMMIT_HASH_STR}")
string(REGEX REPLACE "^(.*)..$" "\\1" GIT_COMMIT_HASH "${GIT_COMMIT_HASH}")
if(NOT GIT_COMMIT_HASH_STR)
  message(WARNING "Could not determine git commit hash")
  set(GIT_COMMIT_HASH 0x00)
  set(GIT_COMMIT_HASH_STR "00")
endif()

# Get the latest *abbreviated* commit hash of the working branch
execute_process(
  COMMAND git log -1 --format=%h --abbrev=7
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_COMMIT_HASH_ABBREV_STR
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(REGEX REPLACE "^(..)" "0x\\1, " GIT_COMMIT_HASH_ABBREV
       "${GIT_COMMIT_HASH_ABBREV_STR}")
string(REGEX REPLACE "^(.*)..$" "\\1" GIT_COMMIT_HASH_ABBREV
       "${GIT_COMMIT_HASH_ABBREV}")
if(NOT GIT_COMMIT_HASH_ABBREV_STR)
  message(WARNING "Could not determine abbreviated git commit hash")
  set(GIT_COMMIT_HASH_ABBREV 0x00)
  set(GIT_COMMIT_HASH_ABBREV_STR "00")
endif()

string(TOUPPER ${PROJECT_NAME} PROJECT_NAME_UC)
configure_file(include/${PROJECT_NAME}/config.h.in
               include/${PROJECT_NAME}/config.h)
configure_file(src/config.c.in src/config.c)

include(GNUInstallDirs)

if(OpenSSL_FOUND)
  add_definitions(-DPTLS_OPENSSL)
  set(PTLS_OPENSSL ptls-openssl)
endif()

add_library(common
  OBJECT
    src/pkt.c src/frame.c src/quic.c src/stream.c src/conn.c src/pn.c
    src/diet.c src/util.c src/tls.c src/recovery.c src/marshall.c
)
add_dependencies(common warpcore ptls-core ${PTLS_OPENSSL} ptls-minicrypto)

add_library(lib${PROJECT_NAME}
            $<TARGET_OBJECTS:common> ${CMAKE_CURRENT_BINARY_DIR}/src/config.c)

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

if(DSYMUTIL AND BUILD_SHARED_LIBS)
  add_custom_command(TARGET lib${PROJECT_NAME} POST_BUILD
    COMMAND ${DSYMUTIL} ARGS *${CMAKE_STATIC_LIBRARY_SUFFIX}
  )
endif()

set(TARGETS common lib${PROJECT_NAME})
foreach(TARGET ${TARGETS})
  add_dependencies(${TARGET} warpcore ptls-core ${PTLS_OPENSSL} ptls-minicrypto)
  target_include_directories(${TARGET}
    SYSTEM PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
      $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    SYSTEM PRIVATE
      ${OPENSSL_ROOT_DIR}/include
      ${LIBEV_INCLUDE}
      ${WARP_INCLUDE}
      $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/external/klib>
    PRIVATE
      $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/external/include>
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
      m warpcore ptls-core ${PTLS_OPENSSL} ptls-minicrypto ${LIBEV_LIB})
    if("${CMAKE_SYSTEM}" MATCHES "Linux")
      target_link_libraries(${TARGET} bsd)
    endif()
    install(TARGETS ${TARGET}
      EXPORT ${TARGET}
      ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
      LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
      RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
  endif()
endforeach()
