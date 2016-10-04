cmake_minimum_required(VERSION 3.6)
project(quickie)
enable_language(C)

set(VERSION_MAJOR 0)
set(VERSION_MINOR 0)
set(VERSION_PATCH 1)

add_subdirectory(doc)
add_subdirectory(external)
add_subdirectory(src)

# add a "distclean" target; see http://stackoverflow.com/a/12055610/1437081
add_custom_target(distclean
  COMMAND
    find . \\\( -name Makefile -or -iwholename '*cmake*' \\\)
      -not -name CMakeLists.txt -and
      -not -path '*external/*-prefix/*' -delete
)
