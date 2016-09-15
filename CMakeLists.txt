cmake_minimum_required(VERSION 3.6)
project(quickie)
enable_testing()
add_subdirectory(test)

# add a "distclean" target; see http://stackoverflow.com/a/12055610/1437081
add_custom_target(distclean
  find . -iwholename '*cmake*' -not -name CMakeLists.txt -delete $<SEMICOLON>
  find . -path '*.vagrant*' -delete $<SEMICOLON>
  rm -r Makefile Testing 'test/*-console.log' 2> /dev/null $<SEMICOLON>
  exit 0
)
