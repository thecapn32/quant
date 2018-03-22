configure_file(test_public_servers.sh test_public_servers.sh COPYONLY)
configure_file(test_public_servers.result test_public_servers.result COPYONLY)
add_test(test_public_servers.sh test_public_servers.sh)

foreach(TARGET diet conn)
  add_executable(test_${TARGET} test_${TARGET}.c)
  target_link_libraries(test_${TARGET} lib${PROJECT_NAME})
  target_include_directories(test_${TARGET}
    PRIVATE
      ${CMAKE_BINARY_DIR}/external/include
      ${CMAKE_SOURCE_DIR}/lib/src
  )
  if(DSYMUTIL)
    add_custom_command(TARGET test_${TARGET} POST_BUILD
      COMMAND ${DSYMUTIL} ARGS $<TARGET_FILE:test_${TARGET}>
    )
  endif()
  add_test(test_${TARGET} test_${TARGET})
endforeach()

