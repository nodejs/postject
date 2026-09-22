enable_testing()

if (NOT LIEF_ELF OR NOT LIEF_PE OR NOT LIEF_MACHO)
  message(FATAL_ERROR "Tests require all LIEF's modules activated" )
endif()

set(LIEF_EXAMPLES_DIRECTORY  "${PROJECT_SOURCE_DIR}/examples")
set(LIEF_EXAMPLES_BINARY_DIR "${PROJECT_BINARY_DIR}/examples")

# Fuzzing
# =======
if(LIEF_USE_MELKOR AND UNIX AND NOT APPLE)
  include(ExternalProject)
  set(MELKOR_VERSION ac2495b) # From the fork: https://github.com/romainthomas/elf_fuzzer
  set(MELKOR_SHA256 SHA256=8cccc4ca5e05e305215cc74761413746b660b76f5869a563f52cec1f23d79f2e)
  set(MELKOR_URL "${THIRD_PARTY_DIRECTORY}/Melkor_ELF_Fuzzer-${MELKOR_VERSION}.zip" CACHE STRING "URL to the Melkor package")

  set(MELKOR_PREFIX      "${CMAKE_CURRENT_BINARY_DIR}/Melkor")
  set(MELKOR_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/Melkor")
  ExternalProject_Add(MELKOR
   PREFIX            ${MELKOR_PREFIX}
   URL               ${MELKOR_URL}
   URL_HASH          ${MELKOR_SHA256}
   INSTALL_DIR       ${MELKOR_INSTALL_DIR}
   UPDATE_COMMAND    ""
   CONFIGURE_COMMAND ""
   INSTALL_COMMAND   ""
   BUILD_COMMAND     make clean && make
   BUILD_IN_SOURCE   ON)

  ExternalProject_get_property(MELKOR SOURCE_DIR)
  set(MELKOR_BINARY "${SOURCE_DIR}/melkor")
  message(STATUS "${MELKOR_BINARY}")
endif()

add_subdirectory(unittests)

add_executable(test_define_conflicts
  test_define_conflicts.cpp
)

set_target_properties(test_define_conflicts
  PROPERTIES CXX_STANDARD           17
             CXX_STANDARD_REQUIRED  ON)

target_link_libraries(test_define_conflicts LIEF::LIEF)

if (LIEF_RUNTIME)
  add_custom_target(tests-runtime)

  function(add_lief_runtime_test_lib TARGET)
    cmake_parse_arguments(ARG "" "" "SOURCES" ${ARGN})

    add_library(${TARGET} SHARED ${ARG_SOURCES})

    set_target_properties(
      ${TARGET}
      PROPERTIES POSITION_INDEPENDENT_CODE ON
                 CXX_STANDARD_REQUIRED     ON)

    target_compile_features(${TARGET} PRIVATE cxx_std_23)

    target_link_libraries(${TARGET} PUBLIC LIEF::LIEF)

    if (LIEF_PYTHON_EDITABLE)
      set(_TEST_INSTALL_PREFIX ${CMAKE_SOURCE_DIR}/api/python/tests/lib)
    else()
      set(_TEST_INSTALL_PREFIX tests/lib/)
    endif()

    install(
      TARGETS ${TARGET}
      LIBRARY DESTINATION ${_TEST_INSTALL_PREFIX}
      RUNTIME DESTINATION ${_TEST_INSTALL_PREFIX}
      BUNDLE  DESTINATION ${_TEST_INSTALL_PREFIX}
      COMPONENT tests)

    add_dependencies(tests-runtime ${TARGET})
  endfunction()

  if (LIEF_RUNTIME_PLATFORM_WINDOWS)
    add_subdirectory(runtime/windows/lib)
  endif()

  if (LIEF_RUNTIME_PLATFORM_OSX)
    add_subdirectory(runtime/osx/lib)
  endif()

  if (LIEF_RUNTIME_PLATFORM_LINUX)
    add_subdirectory(runtime/linux/lib)
  endif()

  if (LIEF_RUNTIME_PLATFORM_ANDROID)
    add_subdirectory(runtime/android/lib)
  endif()
endif()

if (CMAKE_CONFIGURATION_TYPES)
  add_custom_target(check-lief
    COMMAND ${CMAKE_CTEST_COMMAND} --parallel 1 --progress --output-on-failure --build-config "$<CONFIGURATION>")
else()
  add_custom_target(check-lief
    COMMAND ${CMAKE_CTEST_COMMAND} --parallel 1 --progress --output-on-failure)
endif()
