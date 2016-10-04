add_executable(quickie_client quickie_client.c)
target_link_libraries(quickie_client quickie)

add_executable(quickie_server quickie_server.c)
target_link_libraries(quickie_server quickie)

add_custom_target(test-quickie-client
  COMMAND quickie_client
  DEPENDS quic-server quickie_client
)
