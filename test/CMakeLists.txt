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
