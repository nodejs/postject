cmake_minimum_required(VERSION 3.9)
set(CMAKE_CXX_STANDARD 11)

project(postject-tests)

add_executable(c_test test.c)
add_executable(cpp_test test.cpp)

if(WIN32)
  target_compile_options(c_test PRIVATE /W4 /WX)
  target_compile_options(cpp_test PRIVATE /W4 /WX /EHsc)
else()
  target_compile_options(c_test PRIVATE -Wall -Werror)
  target_compile_options(cpp_test PRIVATE -Wall -Werror)
endif()
