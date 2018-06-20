configure_file(test_public_servers.sh test_public_servers.sh COPYONLY)
configure_file(test_public_servers.result test_public_servers.result COPYONLY)
add_test(test_public_servers.sh test_public_servers.sh)

foreach(TARGET diet conn)
  add_executable(test_${TARGET} test_${TARGET}.c)
  target_link_libraries(test_${TARGET} lib${PROJECT_NAME})
  target_include_directories(test_${TARGET}
    PRIVATE
      ${CMAKE_BINARY_DIR}/external/include
      ${CMAKE_SOURCE_DIR}/lib/src
  )
  if(DSYMUTIL)
    add_custom_command(TARGET test_${TARGET} POST_BUILD
      COMMAND ${DSYMUTIL} ARGS $<TARGET_FILE:test_${TARGET}>
    )
  endif()
  add_test(test_${TARGET} test_${TARGET})
endforeach()


if(NOT HAVE_BENCHMARK_H AND (DEFINED ENV{BENCHMARKING} OR BENCHMARKING))
  include(ExternalProject)

  externalproject_add(google-benchmark
    UPDATE_COMMAND ""
    GIT_REPOSITORY https://github.com/google/benchmark
    GIT_SHALLOW 1
    GIT_TAG v1.4.1
    CMAKE_ARGS
      -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}
      -DCMAKE_BUILD_TYPE=Release
    BUILD_BYPRODUCTS ${CMAKE_BINARY_DIR}/lib/libbenchmark.a
  )

  file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/include ${CMAKE_BINARY_DIR}/lib)

  add_library(benchmark STATIC IMPORTED GLOBAL)

  set_target_properties(benchmark PROPERTIES
    IMPORTED_LOCATION ${CMAKE_BINARY_DIR}/lib/libbenchmark.a
    INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_BINARY_DIR}/include
    POSITION_INDEPENDENT_CODE ON
    INTERPROCEDURAL_OPTIMIZATION ${IPO}
  )

  add_dependencies(benchmark google-benchmark)
  set(HAVE_BENCHMARK_H 1)
endif()

if(HAVE_BENCHMARK_H)
  add_executable(bench bench.cc)
  target_link_libraries(bench PUBLIC benchmark pthread libquant)
  target_include_directories(bench
    SYSTEM PRIVATE
      ${CMAKE_SOURCE_DIR}/lib/include
      ${CMAKE_BINARY_DIR}/lib/include
      ${CMAKE_SOURCE_DIR}/lib/src
      $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/external/include>
      ${OPENSSL_ROOT_DIR}/include
    )
  set_target_properties(bench
    PROPERTIES
      POSITION_INDEPENDENT_CODE ON
      INTERPROCEDURAL_OPTIMIZATION ${IPO}
  )
  add_test(bench bench)
endif()

check_c_compiler_flag(-fsanitize=fuzzer HAVE_FUZZER)
if(HAVE_FUZZER)
  add_executable(fuzz fuzz.c)
  target_compile_options(fuzz PRIVATE -fsanitize=fuzzer)
  target_link_libraries(fuzz PUBLIC libquant)
  target_include_directories(fuzz
    SYSTEM PRIVATE
      ${CMAKE_SOURCE_DIR}/lib/include
      ${CMAKE_BINARY_DIR}/lib/include
      ${CMAKE_SOURCE_DIR}/lib/src
      $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/external/include>
      ${OPENSSL_ROOT_DIR}/include
    )
  set_target_properties(fuzz
    PROPERTIES
      POSITION_INDEPENDENT_CODE ON
      INTERPROCEDURAL_OPTIMIZATION ${IPO}
      LINK_FLAGS -fsanitize=fuzzer
  )
endif()
