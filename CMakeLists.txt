cmake_minimum_required(VERSION 3.6)
project(quickie C)
enable_testing()

add_subdirectory(src)
add_subdirectory(test)

# add a "distclean" target; see http://stackoverflow.com/a/12055610/1437081
add_custom_target(distclean
  find . -iwholename '*cmake*' -not -name CMakeLists.txt -delete $<SEMICOLON>
  find . -path '*Testing*' -delete $<SEMICOLON>
  find . -name Makefile -delete $<SEMICOLON>
  rm -r Makefile Testing test/*.log 2> /dev/null $<SEMICOLON>
  true
)
