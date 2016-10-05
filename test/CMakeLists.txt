add_executable(quickie_client quickie_client.c)
target_link_libraries(quickie_client quickie)

add_executable(quickie_server quickie_server.c)
target_link_libraries(quickie_server quickie)

set(DIR ${CMAKE_CURRENT_BINARY_DIR})
set(QC quickie_client)
set(PORT 6121)
add_custom_target(test-quickie-client
  COMMAND
    ${SUDO} ${PKILL} ${QC} sudo || true &&
    ${DAEMONIZE} ${SUDO} ${TCPDUMP} -i lo0 -w ${DIR}/${QC}.pcap port ${PORT} &&
    ${SLEEP} 1 &&
    ${ENV} LLVM_PROFILE_FILE=${QC}.profraw ${DIR}/${QC} &&
    ${SUDO} ${PKILL} ${QC} sudo || true &&
    ${TSHARK} -V -2 -n -d udp.port==${PORT},quic
      -r ${DIR}/${QC}.pcap
  DEPENDS quic-server quickie_client
  VERBATIM
)
