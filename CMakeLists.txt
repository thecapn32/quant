cmake_minimum_required(VERSION 3.9)

project(quant VERSION 0.0.11 LANGUAGES C)

# Check for dependencies before mucking with the compiler flags
include(CheckSymbolExists)

check_symbol_exists(htobe64 endian.h HAVE_ENDIAN_H)
check_symbol_exists(htobe64 sys/endian.h HAVE_SYS_ENDIAN_H)

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  # on Darwin, try and pick up openssl from homebrew
  set(CMAKE_PREFIX_PATH /usr/local/opt/openssl@1.1 /usr/local/opt/openssl)
endif()

find_package(OpenSSL REQUIRED)
string(REGEX REPLACE "/include$" "" OPENSSL_ROOT_DIR ${OPENSSL_INCLUDE_DIR})

find_library(WARP_LIB NAMES sockcore warpcore)
find_path(WARP_INCLUDE warpcore/warpcore.h)
add_library(warpcore STATIC IMPORTED GLOBAL)
if(NOT WARP_INCLUDE)
  set(WARP_INCLUDE ${CMAKE_CURRENT_BINARY_DIR}/external/include)
endif()

if("${CMAKE_SYSTEM}" MATCHES "Linux")
  add_definitions(-D_GNU_SOURCE -DLIBBSD_OVERLAY)
  include_directories(SYSTEM /usr/include/bsd)
endif()

# Build "Debug" type by default
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug
        CACHE STRING "Set build type (default Debug)" FORCE)
endif()

# Generate compile_commands.json for clang-tidy
set(CMAKE_EXPORT_COMPILE_COMMANDS True)

# Use modern C
set(CMAKE_C_STANDARD 11)

# Set general compile flags, if they are supported
include(CheckCCompilerFlag)
foreach(FLAG -march=native -Wextra -Wpedantic -Weverything -Werror
        -fcolor-diagnostics -fdiagnostics-color=always
        -Wno-missing-field-initializers -Wno-disabled-macro-expansion -Wno-cpp
        )
  string(REGEX REPLACE "[-=+]" "_" F ${FLAG})
  check_c_compiler_flag(${FLAG} ${F})
  if(${F})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FLAG}")
  endif()
endforeach()

# Set C flags
foreach(FLAG -Wno-missing-field-initializers -Wno-missing-braces
        -Wno-gnu-statement-expression -Wno-extended-offsetof
        -Wno-redundant-parens)
  string(REGEX REPLACE "[-=+]" "_" F ${FLAG})
  check_c_compiler_flag(${FLAG} ${F})
  if(${F})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FLAG}")
  endif()
endforeach()

# flags for "Debug" and "None" builds
set(CMAKE_C_FLAGS_DEBUG "-O0 -g3")

# disable IPO by default
set(IPO NO)

if(CMAKE_BUILD_TYPE MATCHES Debug)
  # Default debug logging level
  if(NOT DEFINED DLEVEL)
    set(DLEVEL "DBG")
  endif()

  # Enable debug support in the queue.h macros
  add_definitions(-DQUEUE_MACRO_DEBUG_TRASH)

  # See if we can use the address sanitizer
  include(CheckIncludeFile)
  check_include_file(sanitizer/asan_interface.h HAVE_ASAN)
  if(HAVE_ASAN AND NOT NO_SANITIZERS)
    set(CMAKE_REQUIRED_FLAGS -fsanitize=address)
    check_c_compiler_flag("" _fsanitize_address)
    if(_fsanitize_address)
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
    endif()
    unset(CMAKE_REQUIRED_FLAGS)

    # Set some additional flags for Debug builds
    set(FLAGS -fno-omit-frame-pointer -fsanitize-address-use-after-scope
        -fno-optimize-sibling-calls
        -fsanitize=undefined -fsanitize=unsigned-integer-overflow
        -fno-sanitize=alignment -fno-common
    )
    foreach(FLAG ${FLAGS})
      string(REGEX REPLACE "[-=+]" "_" F ${FLAG})
      check_c_compiler_flag(${FLAG} ${F})
      if(${F})
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FLAG}")
      endif()
    endforeach()
  endif()

  if(APPLE)
    find_program(DSYMUTIL dsymutil)
  endif()

  find_program(CPPCHECK NAMES cppcheck)
  if(CPPCHECK)
    message(STATUS "Found cppcheck: ${CPPCHECK}")
    set(CMAKE_C_CPPCHECK ${CPPCHECK} -q --inline-suppr
        --enable=warning,style,performance,portability
        -I external/include -I lib/include -I ${PROJECT_SOURCE_DIR}/lib/include
    )
  endif()

  # Use include-what-you-use to check #includes, if it's installed
  find_program(IWYU NAMES include-what-you-use iwyu)
  if(IWYU)
    message(STATUS "Found include-what-you-use: ${IWYU}")
    string(TOLOWER ${CMAKE_SYSTEM_NAME} CMAKE_SYSTEM_NAME_LC)
    set(CMAKE_C_INCLUDE_WHAT_YOU_USE
        ${IWYU} -Xiwyu
        --mapping_file=${PROJECT_SOURCE_DIR}/misc/${CMAKE_SYSTEM_NAME_LC}.imp)
  endif()

  if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    # Use clang-tidy for extra warnings, if it's installed
    find_program(CLANGTIDY NAMES clang-tidy clang-tidy40 clang-tidy39
                 clang-tidy38 clang-tidy37)
    if(CLANGTIDY)
      message(STATUS "Found clang-tidy: ${CLANGTIDY}")
      set(CLANG_TIDY_CHECKS *
          -cert-err58-cpp
          -clang-diagnostic-unused-command-line-argument
          -google-readability-braces-around-statements
          -hicpp-braces-around-statements
          -google-readability-todo
          -google-runtime-references
          -readability-braces-around-statements
          -google-readability-function-size
          -hicpp-function-size
          -readability-function-size
          -hicpp-signed-bitwise
      )
      string(REPLACE ";" "," CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS}")
      set(CMAKE_C_CLANG_TIDY ${CLANGTIDY}
          -analyze-temporary-dtors -system-headers
          -checks=${CLANG_TIDY_CHECKS}
      )
    endif()
  endif()
else()
  # Default logging level
  if(NOT DEFINED DLEVEL)
    set(DLEVEL "NTE")
  endif()

  # check for INTERPROCEDURAL_OPTIMIZATION support
  include(CheckIPOSupported)
  check_ipo_supported(RESULT IPO)
endif()

# flags for "Release" builds
set(CMAKE_C_FLAGS_RELEASE "-DNDEBUG -Ofast")

# flags for "RelWithDebInfo" builds
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELEASE} -g3")

# set debug level
add_definitions(-DDLEVEL=${DLEVEL})

add_subdirectory(bin)
add_subdirectory(doc)
add_subdirectory(external)
add_subdirectory(lib)
add_subdirectory(misc)

enable_testing()
add_subdirectory(test)
