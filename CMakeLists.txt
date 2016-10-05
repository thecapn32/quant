cmake_minimum_required(VERSION 3.6)
project(quickie)
enable_language(C)

set(VERSION_MAJOR 0)
set(VERSION_MINOR 0)
set(VERSION_PATCH 1)

# Force C11
add_compile_options(-std=c11)

# Warn about everything
add_compile_options(-Wall -Wextra -Weverything -Wpedantic -Werror)

# Optimize
add_compile_options(-flto -march=native -Ofast -pipe)

# Debug
add_compile_options(-g -fprofile-instr-generate)

# Set additional options that are compiler-specific
if("${CMAKE_C_COMPILER_ID}" MATCHES "Clang")
  # see https://llvm.org/bugs/show_bug.cgi?id=21689
  add_compile_options(-Wno-missing-field-initializers)
elseif("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
endif()

# Set linker options that are valid for all linkers
set(CMAKE_SHARED_LINKER_FLAGS "-flto -fprofile-instr-generate")
set(CMAKE_EXE_LINKER_FLAGS "-flto -fprofile-instr-generate")

# Make sure that a bunch of programs we depend on are installed
foreach(PROG daemonize pkill tcpdump tshark sed make sleep)
  string(TOUPPER ${PROG} VARNAME)
  find_program(${VARNAME} ${PROG})
  if(NOT ${VARNAME})
    message(FATAL_ERROR "${PROG} not found; please install it")
  endif()
endforeach()

# find_program() for sudo is unlikely to work, hence the special case; see
# https://cmake.org/pipermail/cmake/2010-September/039520.html
find_program(SUDO sudo)
if(NOT SUDO)
  set(SUDO /usr/bin/sudo)
endif()

add_subdirectory(doc)
add_subdirectory(external)
add_subdirectory(lib)
add_subdirectory(test)

# Add a "distclean" target; see http://stackoverflow.com/a/12055610/1437081
add_custom_target(distclean
  COMMAND
    find . \\\( -name Makefile -or -iwholename '*cmake*' \\\)
      -not -name CMakeLists.txt -and
      -not -path '*external/*-prefix/*' -delete
)
