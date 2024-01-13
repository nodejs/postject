cmake_minimum_required(VERSION 3.9)
set(CMAKE_CXX_STANDARD 11)

project(postject)

# Disable unnecessary LIEF options
option(LIEF_DOC "Build LIEF docs" OFF)
option(LIEF_C_API "C API" OFF)
option(LIEF_PYTHON_API "Build LIEF Python API" OFF)
option(LIEF_ENABLE_JSON "Enable JSON-related APIs" OFF)
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

add_library(postject
    src/postject.cpp
    src/postject.hpp
)
target_link_libraries(postject PUBLIC LIEF::LIEF)

add_executable(postject_wasm
    src/postject_wasm.cpp
)

set_target_properties(postject_wasm PROPERTIES LINK_FLAGS "-sSINGLE_FILE -sMODULARIZE=1 -sALLOW_MEMORY_GROWTH -sINITIAL_MEMORY=268435456 -sMAXIMUM_MEMORY=4294967296 --bind")

if(MSVC)
  set_property(TARGET postject_wasm PROPERTY LINK_FLAGS /NODEFAULTLIB:MSVCRT)
endif()

target_link_libraries(postject_wasm postject)
