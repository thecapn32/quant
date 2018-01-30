# see https://cmake.org/Wiki/CMake_RPATH_handling#Always_full_RPATH
set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
set(LIB ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES ${LIB} isSystemDir)
if("${isSystemDir}" STREQUAL "-1")
  set(CMAKE_INSTALL_RPATH ${LIB})
endif()

include(FindPackageHandleStandardArgs)

find_library(HTTP_PARSER_LIB NAMES http_parser)
if(NOT HTTP_PARSER_LIB)
  message(FATAL_ERROR "http-parser not found")
endif()
find_path(HTTP_PARSER_INCLUDE http_parser.h PATH_SUFFIXES include)
find_package_handle_standard_args(http-parser
  DEFAULT_MSG HTTP_PARSER_LIB HTTP_PARSER_INCLUDE
)
# target_include_directories(${HTTP_PARSER_INCLUDE})

foreach(TARGET client server)
  add_executable(${TARGET} ${TARGET}.c)
  target_link_libraries(${TARGET} lib${PROJECT_NAME} ${HTTP_PARSER_LIB})
  if(DSYMUTIL)
    add_custom_command(TARGET ${TARGET} POST_BUILD
      COMMAND ${DSYMUTIL} ARGS $<TARGET_FILE:${TARGET}>
    )
  endif()
endforeach()

add_custom_target(${PROJECT_NAME} DEPENDS client server)

install(TARGETS client server DESTINATION bin)

