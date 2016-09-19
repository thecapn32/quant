cmake_minimum_required(VERSION 3.6)
project(quickie C)

add_subdirectory(src)
add_subdirectory(test)

# add a "distclean" target; see http://stackoverflow.com/a/12055610/1437081
add_custom_target(distclean
  COMMAND
    find . \\\( -name Makefile -or -iwholename '*cmake*' \\\)
      -not -name CMakeLists.txt -and
      -not -path '*test/proto-quic*' -delete
)
