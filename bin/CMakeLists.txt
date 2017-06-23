include(GNUInstallDirs)

# see https://cmake.org/Wiki/CMake_RPATH_handling#Always_full_RPATH
set(LIB ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set(CMAKE_INSTALL_RPATH ${LIB})
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES ${LIB} isSystemDir)
if("${isSystemDir}" STREQUAL "-1")
   set(CMAKE_INSTALL_RPATH ${LIB})
endif()

add_executable(client client.c)
target_link_libraries(client ${PROJECT_NAME}_dyn)

add_executable(server server.c)
target_link_libraries(server ${PROJECT_NAME}_dyn)

install(TARGETS client server DESTINATION bin)
