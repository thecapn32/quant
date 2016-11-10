add_executable(quickie_client quickie_client.c)
target_link_libraries(quickie_client quickie)

add_executable(quickie_server quickie_server.c)
target_link_libraries(quickie_server quickie)

set(DIR ${CMAKE_CURRENT_BINARY_DIR})
set(QC quickie_client)
set(PORT 6121)
add_custom_target(test-quickie-client
  COMMAND
    ${RM} -f ${DIR}/${QC}.profraw ${DIR}/${QC}.pcap ${DIR}/${QC}.core || true &&
    ${SUDO} ${PKILL} ${QC} sudo || true &&
    ${DAEMON} -- ${SUDO} ${TCPDUMP} -i lo0 -w ${DIR}/${QC}.pcap port ${PORT} &&
    ${SLEEP} 1 &&
    ${ENV} LLVM_PROFILE_FILE=${QC}.profraw ${DIR}/${QC} || true &&
    ${SUDO} ${PKILL} ${QC} sudo || true &&
    ${TAIL} ${DIR}/../external/quic_server.log || true
  DEPENDS quic-server quickie_client
  VERBATIM
)

add_custom_target(tshark-quickie-client-pcap
  COMMAND
    ${TSHARK} -V -2 -n -d udp.port==${PORT},quic -O quic -r ${DIR}/${QC}.pcap
  VERBATIM
)

# allow a target called "test"
cmake_policy(SET CMP0037 OLD)
add_custom_target(test
  COMMAND
    ${TMUX} new-session -d "${DIR}/quickie_server" \;
      split-window "${SLEEP} 1 ; ${DIR}/quickie_client -p 8443" \;
      set remain-on-exit on \; attach
  DEPENDS quickie_server quickie_client
  VERBATIM
)
