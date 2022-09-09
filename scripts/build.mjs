#!/usr/bin/env zx

// TODO - Check for emsdk before continuing

// Create build folder if needed
if (!(await fs.exists("./build"))) {
  await $`mkdir build`;
}
cd("build");

// Build with emsdk
await $`emcmake cmake -G Ninja ..`;
await $`cmake --build .`; // TODO - Pass jobs and allow overriding for CI

// Copy artifacts to dist
await fs.copy("postject.wasm", "../dist/postject.wasm");
await fs.copy("postject.js", "../dist/postject.js");
await fs.copy("../src/main.js", "../dist/main.js");
await fs.copy("../postject-api.h", "../dist/postject-api.h");

// Build tests
if (!(await fs.exists("./test"))) {
  await $`mkdir test`;
}

cd("test");
await $`cmake -G Ninja ../../test`;
await $`cmake --build .`;
