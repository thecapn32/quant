# if("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
# elseif("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
# endif()

# find_library(NSS_LIB nss HINTS /usr/local/opt/nss/lib)
# if(NOT NSS_LIB)
#   message(FATAL_ERROR "nss library not found")
# endif()

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
