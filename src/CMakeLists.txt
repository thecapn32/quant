include_directories(${quickie_SOURCE_DIR}/include)

add_compile_options(-std=gnu11 -Wall -Wextra -Weverything -pedantic)
# if("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
# elseif("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
# endif()

add_library(quickie quic.c debug.c)
target_link_libraries(quickie tommy)

add_executable(quickie_client quickie_client.c)
target_link_libraries(quickie_client quickie)
