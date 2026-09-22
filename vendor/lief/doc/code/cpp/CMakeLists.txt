cmake_minimum_required(VERSION 3.30)
project(lief-doc-code CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (NOT TARGET LIB_LIEF)
  find_package(LIEF REQUIRED)
endif()

file(GLOB LIEF_DOC_CODE_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

add_library(lief-doc-code OBJECT ${LIEF_DOC_CODE_SOURCES})
target_link_libraries(lief-doc-code PRIVATE LIEF::LIEF)
target_compile_options(lief-doc-code PRIVATE
  -Wno-unused-variable
  -Wno-unused-parameter
)
