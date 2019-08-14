configure_file(test_public_servers.sh test_public_servers.sh COPYONLY)
configure_file(test_public_servers.result test_public_servers.result COPYONLY)
add_test(test_public_servers.sh test_public_servers.sh)

foreach(TARGET diet conn)
  add_executable(test_${TARGET} test_${TARGET}.c
    ${CMAKE_CURRENT_BINARY_DIR}/dummy.key ${CMAKE_CURRENT_BINARY_DIR}/dummy.crt)
  target_link_libraries(test_${TARGET} lib${PROJECT_NAME})
  target_include_directories(test_${TARGET}
    PRIVATE
      ${PROJECT_BINARY_DIR}/external/include
      ${PROJECT_SOURCE_DIR}/lib/src
  )
  if(DSYMUTIL)
    add_custom_command(TARGET test_${TARGET} POST_BUILD
      COMMAND ${DSYMUTIL} ARGS $<TARGET_FILE:test_${TARGET}>
    )
  endif()
  add_test(test_${TARGET} test_${TARGET})
endforeach()

add_custom_command(
  OUTPUT
    ${CMAKE_CURRENT_BINARY_DIR}/dummy.key
    ${CMAKE_CURRENT_BINARY_DIR}/dummy.crt
  COMMAND
    ${OPENSSL_ROOT_DIR}/bin/openssl
  ARGS
    req -batch -new -newkey rsa:2048 -sha256 -days 9365
    -nodes -x509 -subj "/" -addext "subjectAltName = DNS:example.org"
    -keyout ${CMAKE_CURRENT_BINARY_DIR}/dummy.key
    -out ${CMAKE_CURRENT_BINARY_DIR}/dummy.crt || true
)

if(HAVE_BENCHMARK_H)
  set(TARGETS bench bench_conn)
  if(HAVE_NETMAP_H)
    set(TARGETS ${TARGETS} bench-warp bench_conn-warp)
  endif()

  foreach(TARGET ${TARGETS})
    if(${TARGET} MATCHES ".*-warp")
      string(REGEX REPLACE "-warp$" "" SOURCE ${TARGET})
      add_executable(${TARGET} ${SOURCE}.cc)
      target_link_libraries(${TARGET} PUBLIC benchmark pthread libquant-warp)
    else()
      add_executable(${TARGET} ${TARGET}.cc)
      target_link_libraries(${TARGET} PUBLIC benchmark pthread libquant)
    endif()

    if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin" AND CMAKE_COMPILER_IS_GNUCC)
      target_link_options(${TARGET} PUBLIC -lc++)
    endif()

    target_include_directories(${TARGET}
      SYSTEM PRIVATE
        ${OPENSSL_ROOT_DIR}/include
      PRIVATE
        ${PROJECT_SOURCE_DIR}/lib/include
        ${PROJECT_BINARY_DIR}/lib/include
        ${PROJECT_SOURCE_DIR}/lib/src
      SYSTEM PRIVATE
        ${OPENSSL_ROOT_DIR}/include
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/lib/deps/picotls/include>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/lib/deps/warpcore/lib/include>
        $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/lib/deps/warpcore/lib/include>
        )
    set_target_properties(${TARGET}
      PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        INTERPROCEDURAL_OPTIMIZATION ${IPO}
    )
    if(DSYMUTIL)
      add_custom_command(TARGET ${TARGET} POST_BUILD
        COMMAND ${DSYMUTIL} ARGS ${TARGET}
      )
    endif()
    add_test(${TARGET} ${TARGET})
  endforeach()
endif()

if(HAVE_FUZZER)
  foreach(TARGET fuzz_pkt fuzz_frm)
    add_executable(${TARGET} ${TARGET}.c)
    target_link_libraries(${TARGET} PUBLIC libquant)
    target_include_directories(${TARGET}
      SYSTEM PRIVATE
        ${OPENSSL_ROOT_DIR}/include
      PRIVATE
        ${PROJECT_SOURCE_DIR}/lib/include
        ${PROJECT_BINARY_DIR}/lib/include
        ${PROJECT_SOURCE_DIR}/lib/src
        ${OPENSSL_ROOT_DIR}/include
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/lib/deps/picotls/include>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/lib/deps/warpcore/lib/include>
        $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/lib/deps/warpcore/lib/include>
      )
    set_target_properties(${TARGET}
      PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        INTERPROCEDURAL_OPTIMIZATION ${IPO}
        LINK_FLAGS -fsanitize=fuzzer,address,undefined
    )
  endforeach()
endif()
