include_directories(${quickie_SOURCE_DIR}/include)

set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} -std=gnu11 -Wall -Wextra -Weverything -pedantic")
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
endif()

add_executable(quickie_client quickie_client.c)
