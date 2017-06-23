include_directories(${CMAKE_SOURCE_DIR}/lib/src
  SYSTEM ${CMAKE_BINARY_DIR}/external/include
)

add_executable(test_diet test_diet.c)
target_link_libraries(test_diet ${PROJECT_NAME}_dyn)
add_test(test_diet test_diet)

add_executable(test_conn test_conn.c)
target_link_libraries(test_conn ${PROJECT_NAME}_dyn)
add_test(test_conn test_conn)
