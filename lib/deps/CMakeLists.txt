set(BUILD_DOCUMENTATION 0)

unset(CMAKE_C_FLAGS)
unset(CMAKE_C_CLANG_TIDY)
unset(CMAKE_C_INCLUDE_WHAT_YOU_USE)
unset(CMAKE_C_CPPCHECK)

unset(CMAKE_CXX_FLAGS)
unset(CMAKE_CXX_CLANG_TIDY)
unset(CMAKE_CXX_INCLUDE_WHAT_YOU_USE)
unset(CMAKE_CXX_CPPCHECK)

set(CMAKE_POLICY_DEFAULT_CMP0048 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0042 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0054 NEW)

get_directory_property(DEFS COMPILE_DEFINITIONS)
list(APPEND DEFS NDEBUG)
set_directory_properties(PROPERTIES COMPILE_DEFINITIONS "${DEFS}")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
  set(IPO False)
endif()

add_subdirectory(warpcore)
add_subdirectory(picotls)

set(PTLS_CORE_LIBRARY
  ${CMAKE_CURRENT_BINARY_DIR}/picotls/libpicotls-core.a
)

set(PTLS_MINICRYPTO_LIBRARY
  ${CMAKE_CURRENT_BINARY_DIR}/picotls/libpicotls-minicrypto.a
)

set(PTLS_OPENSSL_LIBRARY
  ${CMAKE_CURRENT_BINARY_DIR}/picotls/libpicotls-openssl.a
)

# add_subdirectory(picoquic)
