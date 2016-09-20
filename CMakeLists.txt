cmake_minimum_required(VERSION 3.6)
project(quickie C)

add_subdirectory(src)
add_subdirectory(external)

# add a "distclean" target; see http://stackoverflow.com/a/12055610/1437081
add_custom_target(distclean
  COMMAND
    find . \\\( -name Makefile -or -iwholename '*cmake*' \\\)
      -not -name CMakeLists.txt -and
      -not -path '*external/*-prefix/*' -delete
)


# Allow a target named "test" below, which his normally reserved by cmake
# https://github.com/ros/ros/pull/61
cmake_policy(SET CMP0037 OLD)

find_program(NC nc)
find_program(CAT cat)
find_program(VAGRANT vagrant)

add_custom_target(quic-server
  COMMAND
    cd external &&
    ${VAGRANT} ssh -c "\
      pkill quic_server ; \
      /usr/bin/nohup ${BIN}/quic_server --port=6121 \
        --certificate_file=${CERTS}/out/leaf_cert.pem \
        --key_file=${CERTS}/out/leaf_cert.pkcs8 \
        > /vagrant/quic_server.log 2>&1 & \
      sleep 1 \
  "
  DEPENDS proto-quic
  VERBATIM
)

add_custom_target(test-nc
  COMMAND ${NC} -v -D -n -u -w 1 127.0.0.1 6121 < ${CAT} Vagrantfile
  DEPENDS quic-server
)

add_custom_target(test-quickie-client
  COMMAND quickie_client
  DEPENDS quic-server
)

add_custom_target(test
  DEPENDS test-nc test-quickie-client
)
