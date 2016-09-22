include_directories(${quickie_SOURCE_DIR}/include)

add_compile_options(-std=gnu11 -Wall -Wextra -Weverything -pedantic -Wno-padded)
# if("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
# elseif("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
# endif()

# find_library(NSS_LIB nss HINTS /usr/local/opt/nss/lib)
# if(NOT NSS_LIB)
#   message(FATAL_ERROR "nss library not found")
# endif()

find_package(PkgConfig)
# XXX the path below is only valid when nss was installed via homebrew
set(NSS_PKG_PATH /usr/local/opt/nss/lib/pkgconfig)
set(ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:${NSS_PKG_PATH}")
pkg_check_modules(NSS nss)
find_path(NSS_INCLUDE_DIR NAMES nss.h PATHS ${NSS_INCLUDE_DIRS})
find_library(NSS_LIBRARY NAMES nss PATHS ${NSS_LIBRARY_DIRS})
message(STATUS "${NSS_INCLUDE_DIRS} ${NSS_LIBRARY_DIRS}")
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(nss DEFAULT_MSG NSS_LIBRARY NSS_INCLUDE_DIR)
mark_as_advanced(NSS_INCLUDE_DIR NSS_LIBRARY)
set(NSS_LIBRARIES ${NSS_LIBRARY})
set(NSS_INCLUDE_DIRS ${NSS_INCLUDE_DIR})

add_library(quickie quic.c debug.c)
include_directories(${NSS_INCLUDE_DIRS})
target_link_libraries(quickie tommy ${NSS_LIBRARIES})

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
