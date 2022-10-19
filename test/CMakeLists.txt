cmake_minimum_required(VERSION 3.9)
set(CMAKE_CXX_STANDARD 11)

if(WIN32)
  set(CMAKE_CXX_FLAGS "/W4 /WX /EHsc")
  set(CMAKE_C_FLAGS "/W4 /WX")
else()
  set(CMAKE_CXX_FLAGS "-Wall -Werror")
  set(CMAKE_C_FLAGS "-Wall -Werror")
endif()

project(postject-tests)

add_executable(c_test test.c)
add_executable(cpp_test test.cpp)
