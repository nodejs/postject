cmake_minimum_required(VERSION 3.24)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(postject)

# LIEF bundles fmt/spdlog, whose memory_buffer calls global `free` from a template
# whose definition point (under Emscripten's libc++ headers) doesn't yet have
# <cstdlib> visible -- ADL can't find it, so the build errors. Force-include
# <cstdlib> into every TU so `free`/`malloc` are always declared.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -include cstdlib")

include(FetchContent)

# Disable unnecessary LIEF options (set before LIEF is configured).
set(LIEF_DOC OFF CACHE BOOL "" FORCE)
set(LIEF_C_API OFF CACHE BOOL "" FORCE)
set(LIEF_PYTHON_API OFF CACHE BOOL "" FORCE)
set(LIEF_ENABLE_JSON OFF CACHE BOOL "" FORCE)
set(LIEF_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LIEF_TESTS OFF CACHE BOOL "" FORCE)
set(LIEF_INSTALL OFF CACHE BOOL "" FORCE)
set(LIEF_LOGGING OFF CACHE BOOL "" FORCE)
set(LIEF_LOGGING_DEBUG OFF CACHE BOOL "" FORCE)

if(MSVC)
  set(LIEF_USE_CRT_RELEASE "MT" CACHE STRING "LIEF CRT option")
endif()

FetchContent_Declare(
  LIEF
  GIT_REPOSITORY https://github.com/lief-project/LIEF.git
  GIT_TAG 0.17.6
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(LIEF)

add_executable(postject src/postject.cpp)
set_target_properties(postject PROPERTIES LINK_FLAGS "-sSINGLE_FILE -sMODULARIZE=1 -sALLOW_MEMORY_GROWTH -sINITIAL_MEMORY=268435456 -sMAXIMUM_MEMORY=4294967296 --bind")

if(MSVC)
  set_property(TARGET postject PROPERTY LINK_FLAGS /NODEFAULTLIB:MSVCRT)
endif()

target_link_libraries(postject PUBLIC LIEF::LIEF)
