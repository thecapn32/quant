add_executable(client client.c)
target_link_libraries(client ${PROJECT_NAME})

add_executable(server server.c)
target_link_libraries(server ${PROJECT_NAME})
