configure_file(version.h.in version.h)

find_library(LIBNSS_LIB NAMES nss nss3 PATHS /usr/local/opt/nss/lib)
find_path(LIBNSS_INCLUDE nss.h PATH_SUFFIXES include/nss include)
find_package_handle_standard_args(libnss DEFAULT_MSG LIBNSS_LIB LIBNSS_INCLUDE)

find_library(LIBEV_LIB NAMES ev)
find_path(LIBEV_INCLUDE ev.h PATH_SUFFIXES include/ev include)
find_package_handle_standard_args(libev DEFAULT_MSG LIBEV_LIB LIBEV_INCLUDE)

add_library(quickie util.c fnv_1a.c pkt.c quic.c)
target_include_directories(quickie PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(quickie tommy ${NSS_LIB} ${LIBEV_LIB})
