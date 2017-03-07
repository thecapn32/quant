check_symbol_exists(htobe64 endian.h HAVE_ENDIAN_H)
check_symbol_exists(htobe64 sys/endian.h HAVE_SYS_ENDIAN_H)

string(TOUPPER ${PROJECT_NAME} PROJECT_NAME_UC)
configure_file(config.h.in config.h)
configure_file(config.c.in config.c)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

# find_library(LIBNSS_LIB NAMES nss nss3 PATHS /usr/local/opt/nss/lib)
# find_path(LIBNSS_INCLUDE nss.h
#   PATH_SUFFIXES include/nss include PATHS /usr/local/opt/nss)
# find_package_handle_standard_args(libnss
#   DEFAULT_MSG LIBNSS_LIB LIBNSS_INCLUDE)
# include_directories(${LIBNSS_INCLUDE})

find_library(LIBEV_LIB NAMES ev)
find_path(LIBEV_INCLUDE ev.h PATH_SUFFIXES include/ev include)
find_package_handle_standard_args(libev DEFAULT_MSG LIBEV_LIB LIBEV_INCLUDE)
# include_directories(${LIBEV_INCLUDE})

set(${PROJECT_NAME}_sources
  fnv_1a.c pkt.c frame.c quic.c stream.c conn.c
  ${CMAKE_CURRENT_BINARY_DIR}/config.c)
add_library(${PROJECT_NAME} STATIC ${${PROJECT_NAME}_sources})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

find_package(Threads)
target_link_libraries(${PROJECT_NAME}
  warpcore tommy ${LIBEV_LIB} ${CMAKE_THREAD_LIBS_INIT}) # ${NSS_LIB}

