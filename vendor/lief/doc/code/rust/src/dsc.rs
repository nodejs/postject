pub fn iterate_libraries(some_dyld_cache: &lief::dsc::DyldSharedCache) {
    // lief-doc: libraries-start
    let dyld_cache: &lief::dsc::DyldSharedCache = some_dyld_cache;

    for dylib in dyld_cache.libraries() {
        println!("0x{:016x}: {}", dylib.address(), dylib.path());
    }
    // lief-doc: libraries-end
}

pub fn extract(some_dyld_cache: &lief::dsc::DyldSharedCache) {
    // lief-doc: extract-start
    let dyld_cache: &lief::dsc::DyldSharedCache = some_dyld_cache;

    let liblockdown = dyld_cache.find_lib_from_name("liblockdown.dylib").unwrap();

    let macho = liblockdown.get().unwrap();

    for segment in macho.segments() {
        println!("{}", segment.name());
    }
    // lief-doc: extract-end
}

pub fn write_back(some_dyld_cache: &lief::dsc::DyldSharedCache) {
    // lief-doc: write-start
    let dyld_cache: &lief::dsc::DyldSharedCache = some_dyld_cache;

    let liblockdown = dyld_cache.find_lib_from_name("liblockdown.dylib").unwrap();
    let mut macho = liblockdown.get().unwrap();

    macho.write("on-disk-liblockdown.dylib");
    // lief-doc: write-end
}

pub fn load() {
    // lief-doc: load-start
    let dyld_cache = lief::dsc::load_from_path("macos-15.0.1/", "");
    // lief-doc: load-end
}
