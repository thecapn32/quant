include_directories(${quickie_SOURCE_DIR}/include)

add_compile_options(-std=gnu11 -Wall -Wextra -Weverything -pedantic -Wno-padded)
# if("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
# elseif("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
# endif()

add_library(quickie quic.c debug.c)
target_link_libraries(quickie tommy)

add_executable(quickie_client quickie_client.c)
target_link_libraries(quickie_client quickie)

add_executable(quickie_server quickie_server.c)
target_link_libraries(quickie_server quickie)


# Allow a target named "test" below, which his normally reserved by cmake
# https://github.com/ros/ros/pull/61
# cmake_policy(SET CMP0037 OLD)

add_custom_target(test-quickie-client
  COMMAND quickie_client
  DEPENDS quic-server quickie_client
)
