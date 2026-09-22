add_lief_runtime_test_lib(runtime-base-addr SOURCES base_addr.cpp)

target_link_options(runtime-base-addr PRIVATE -Wl,--image-base=0x3000)
