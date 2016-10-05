configure_file(version.h.in version.h)

find_package(PkgConfig)
# XXX the path below is only valid when nss was installed via homebrew
set(NSS_PKG_PATH /usr/local/opt/nss/lib/pkgconfig)
set(ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:${NSS_PKG_PATH}")
pkg_check_modules(NSS nss)
find_path(NSS_INCLUDE_DIR NAMES nss.h PATHS ${NSS_INCLUDE_DIRS})
find_library(NSS_LIBRARY NAMES nss PATHS ${NSS_LIBRARY_DIRS})
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(nss DEFAULT_MSG NSS_LIBRARY NSS_INCLUDE_DIR)
mark_as_advanced(NSS_INCLUDE_DIR NSS_LIBRARY)
set(NSS_LIBRARIES ${NSS_LIBRARY})
set(NSS_INCLUDE_DIRS ${NSS_INCLUDE_DIR})

add_library(quickie debug.c fnv_1a.c quic.c)
target_include_directories(quickie PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${NSS_INCLUDE_DIRS})
target_link_libraries(quickie tommy ${NSS_LIBRARIES})
