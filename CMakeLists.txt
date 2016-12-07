cmake_minimum_required(VERSION 3.0)

project(quant VERSION 0.0.1 LANGUAGES C)

# Set general compile flags, if they are supported
include(CheckCCompilerFlag)
foreach(FLAG -std=c11 -march=native -Wextra -Wpedantic -Weverything -Werror
        -Wno-missing-field-initializers -Wno-missing-braces)
  string(REGEX REPLACE "[-=]" "" F ${FLAG})
  check_c_compiler_flag(${FLAG} ${F})
  if(${F})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FLAG}")
  endif()
endforeach()

# flags for "Debug" and "None" builds
set(CMAKE_C_FLAGS_DEBUG "-O0 -g")

# flags for "Release" builds
set(CMAKE_C_FLAGS_RELEASE "-DNDEBUG -Ofast")

# flags for "RelWithDebInfo" builds
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-DNDEBUG -Ofast -g")

# Check if _GNU_SOURCE is available.
include(CheckSymbolExists)
check_symbol_exists(__GNU_LIBRARY__ "features.h" _GNU_SOURCE)
if(_GNU_SOURCE)
  add_definitions(-D_GNU_SOURCE)
endif()

# Build "Debug" type by default
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug
        CACHE STRING "Set build type (default Debug)" FORCE)
endif()

# Extract compile options into variable, for doxygen's CLANG_ASSISTED_PARSING
get_property(COMPILE_OPTIONS DIRECTORY PROPERTY COMPILE_OPTIONS)
string(REPLACE ";" " " COMPILE_OPTIONS "${COMPILE_OPTIONS}")

# Make sure that a bunch of programs we depend on are installed
include(FindPackageHandleStandardArgs)
foreach(PROG daemon pkill tcpdump tshark sed make sleep rm
        vagrant cat tail tmux)
  string(TOUPPER ${PROG} VARNAME)
  find_program(${VARNAME} ${PROG})
  mark_as_advanced(${VARNAME})
  find_package_handle_standard_args(${PROG} DEFAULT_MSG ${VARNAME})
endforeach()

# find_program() for sudo is unlikely to work, hence the special case; see
# https://cmake.org/pipermail/cmake/2010-September/039520.html
find_program(SUDO sudo)
if(NOT SUDO)
  set(SUDO /usr/bin/sudo)
endif()
mark_as_advanced(SUDO)
find_package_handle_standard_args(sudo DEFAULT_MSG SUDO)

add_subdirectory(bin)
add_subdirectory(doc)
add_subdirectory(external)
add_subdirectory(lib)

# Add a "distclean" target; see http://stackoverflow.com/a/12055610/1437081
add_custom_target(distclean COMMAND git clean -f -x)
