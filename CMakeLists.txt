cmake_minimum_required(VERSION 3.6)
project(quickie)
enable_language(C)

set(VERSION_MAJOR 0)
set(VERSION_MINOR 0)
set(VERSION_PATCH 1)

# set options that are valid for all compilers
add_compile_options(-std=c11 -Wall -Wextra -Weverything -Wpedantic
                    -fno-strict-aliasing -flto -march=native -O2)

# set options that are compiler-specific
if("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
elseif("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
endif()

# set linker options that are valid for all linkers
set (CMAKE_SHARED_LINKER_FLAGS "-flto")
set (CMAKE_EXE_LINKER_FLAGS "-flto")

add_subdirectory(doc)
add_subdirectory(external)
add_subdirectory(lib)
add_subdirectory(test)

# add a "distclean" target; see http://stackoverflow.com/a/12055610/1437081
add_custom_target(distclean
  COMMAND
    find . \\\( -name Makefile -or -iwholename '*cmake*' \\\)
      -not -name CMakeLists.txt -and
      -not -path '*external/*-prefix/*' -delete
)
