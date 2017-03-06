add_executable(client client.c)
target_link_libraries(client ${PROJECT_NAME})

add_executable(server server.c)
target_link_libraries(server ${PROJECT_NAME})

set(PORT 6121)
add_custom_target(test-${PROJECT_NAME}-client
  COMMAND
    ls -l &&
    rm -f client.profraw client.pcap client.core || true &&
    sudo pkill client sudo || true &&
    daemon -- sudo tcpdump -i lo0 -w client.pcap port ${PORT} &&
    sleep 1 &&
    env LLVM_PROFILE_FILE=client.profraw ./client || true &&
    sudo pkill client sudo || true &&
    tail ../external/quic_server.log || true
  DEPENDS quic-server client
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  VERBATIM
)

add_custom_target(tshark-${PROJECT_NAME}-client-pcap
  COMMAND
    tshark -V -2 -n -d udp.port==${PORT},quic -O quic -r client.pcap
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  VERBATIM
)

# allow a target called "test"
cmake_policy(SET CMP0037 OLD)
add_custom_target(test
  COMMAND
    rm -f client.profraw client.pcap client.core
      server.profraw server.pcap server.core || true &&
    tmux new-session -d "./server" \;
      split-window "sleep 1 ; ./client -p 8443" \;
      set remain-on-exit on \; attach
  DEPENDS server client
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  VERBATIM
)
