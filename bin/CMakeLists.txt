include(GNUInstallDirs)
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

add_executable(client client.c)
target_link_libraries(client ${PROJECT_NAME})

add_executable(server server.c)
target_link_libraries(server ${PROJECT_NAME})

install(TARGETS client server DESTINATION bin)
