string(TOUPPER ${PROJECT_NAME} PROJECT_NAME_UC)
configure_file(include/${PROJECT_NAME}/config.h.in include/${PROJECT_NAME}/config.h)
configure_file(src/config.c.in src/config.c)

include(GNUInstallDirs)
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

# find_library(LIBNSS_LIB NAMES nss nss3 PATHS /usr/local/opt/nss/lib)
# find_path(LIBNSS_INCLUDE nss.h
#   PATH_SUFFIXES include/nss include PATHS /usr/local/opt/nss)
# find_package_handle_standard_args(libnss
#   DEFAULT_MSG LIBNSS_LIB LIBNSS_INCLUDE)
# include_directories(${LIBNSS_INCLUDE})

set(${PROJECT_NAME}_sources
  src/fnv_1a.c src/pkt.c src/frame.c src/quic.c src/stream.c src/conn.c
  ${CMAKE_CURRENT_BINARY_DIR}/src/config.c)

add_library(${PROJECT_NAME}_static
            STATIC ${${PROJECT_NAME}_sources})

set_target_properties(${PROJECT_NAME}_static
                      PROPERTIES
                        INTERPROCEDURAL_OPTIMIZATION True
                        OUTPUT_NAME ${PROJECT_NAME}
                        VERSION ${PROJECT_VERSION}
                        SOVERSION ${PROJECT_VERSION_MAJOR})

target_include_directories(${PROJECT_NAME}_static
                           PUBLIC
                             $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                             $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
                             $<INSTALL_INTERFACE:include>
                           PRIVATE src external/include)

install(TARGETS ${PROJECT_NAME}_static EXPORT ${PROJECT_NAME}_static_config
        ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR})

add_library(${PROJECT_NAME}
            SHARED ${${PROJECT_NAME}_sources})

set_target_properties(${PROJECT_NAME}
                      PROPERTIES
                        INTERPROCEDURAL_OPTIMIZATION True
                        OUTPUT_NAME ${PROJECT_NAME}
                        VERSION ${PROJECT_VERSION}
                        SOVERSION ${PROJECT_VERSION_MAJOR})

target_include_directories(${PROJECT_NAME}
                           PUBLIC
                             $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                             $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
                             $<INSTALL_INTERFACE:include>
                           PRIVATE src external/include)

install(TARGETS ${PROJECT_NAME} EXPORT ${PROJECT_NAME}_config
        ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR})

install(DIRECTORY include/${PROJECT_NAME}
        DESTINATION include
        FILES_MATCHING PATTERN "*.h")

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/include/${PROJECT_NAME}/config.h
        DESTINATION include/${PROJECT_NAME})

target_link_libraries(${PROJECT_NAME}_static
  warpcore ${LIBEV_LIB} Threads::Threads) # ${NSS_LIB}

target_link_libraries(${PROJECT_NAME}
  warpcore ${LIBEV_LIB} Threads::Threads) # ${NSS_LIB}
