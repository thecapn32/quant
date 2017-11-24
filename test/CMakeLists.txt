foreach(TARGET diet conn)
  add_executable(test_${TARGET} test_${TARGET}.c)
  target_link_libraries(test_${TARGET} ${PROJECT_NAME})
  target_include_directories(test_${TARGET}
    PRIVATE
      ${CMAKE_BINARY_DIR}/external/include
      ${CMAKE_SOURCE_DIR}/lib/src
  )
  add_test(test_${TARGET} test_${TARGET})
endforeach()
