add_executable(quickie_client quickie_client.c)
target_link_libraries(quickie_client quickie)

add_executable(quickie_server quickie_server.c)
target_link_libraries(quickie_server quickie)

set(QC quickie_client)
set(QS quickie_server)
set(PORT 6121)
add_custom_target(test-quickie-client
  COMMAND
    ${RM} -f ${QC}.profraw ${QC}.pcap ${QC}.core || true &&
    ${SUDO} ${PKILL} ${QC} sudo || true &&
    ${DAEMON} -- ${SUDO} ${TCPDUMP} -i lo0 -w ${QC}.pcap port ${PORT} &&
    ${SLEEP} 1 &&
    ${ENV} LLVM_PROFILE_FILE=${QC}.profraw ${QC} || true &&
    ${SUDO} ${PKILL} ${QC} sudo || true &&
    ${TAIL} ../external/quic_server.log || true
  DEPENDS quic-server quickie_client
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  VERBATIM
)

add_custom_target(tshark-quickie-client-pcap
  COMMAND
    ${TSHARK} -V -2 -n -d udp.port==${PORT},quic -O quic -r ${QC}.pcap
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  VERBATIM
)

# allow a target called "test"
cmake_policy(SET CMP0037 OLD)
add_custom_target(test
  COMMAND
    ${RM} -f ${QC}.profraw ${QC}.pcap ${QC}.core
      ${QS}.profraw ${QS}.pcap ${QS}.core || true &&
    ${TMUX} new-session -d "./quickie_server" \;
      split-window "${SLEEP} 1 ; ./quickie_client -p 8443" \;
      set remain-on-exit on \; attach
  DEPENDS quickie_server quickie_client
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  VERBATIM
)
