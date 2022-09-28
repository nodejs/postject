cmake_minimum_required(VERSION 3.9)
set(CMAKE_CXX_STANDARD 11)

project(postject)

# Disable unnecessary LIEF options
option(LIEF_DOC "Build LIEF docs" OFF)
option(LIEF_PYTHON_API "Build LIEF Python API" OFF)
option(LIEF_EXAMPLES "Build LIEF examples" OFF)
option(LIEF_TESTS "Build LIEF tests" OFF)
option(LIEF_ART "Build LIEF with ART module" OFF)
option(LIEF_DEX "Build LIEF with DEX module" OFF)
option(LIEF_VDEX "Build LIEF with VDEX module" OFF)
option(LIEF_OAT "Build LIEF with OAT module" OFF)

if(MSVC)
  set(LIEF_USE_CRT_RELEASE "MT" CACHE STRING "LIEF CRT option")
endif()

add_subdirectory(vendor/lief)

add_executable(postject src/postject.cpp)
set_target_properties(postject PROPERTIES LINK_FLAGS "-sMODULARIZE=1 -sALLOW_MEMORY_GROWTH --bind")

if(MSVC)
  set_property(TARGET postject PROPERTY LINK_FLAGS /NODEFAULTLIB:MSVCRT)
endif()

target_link_libraries(postject PUBLIC LIEF::LIEF)
