#!/usr/bin/env zx

let jobs = argv.jobs;

if (!jobs) {
  const platform = os.platform();

  if (platform === "darwin") {
    // nproc doesn't work on CircleCI
    jobs = await $`sysctl -n hw.logicalcpu`;
  } else if (platform === "win32") {
    jobs = process.env["NUMBER_OF_PROCESSORS"];
  } else {
    jobs = await $`nproc`;
  }
}

try {
  await which("emcmake");
} catch {
  console.log("ERROR: Couldn't find `emcmake`, is emsdk installed?");
  process.exit(1);
}

// Create build folder if needed
if (!(await fs.exists("./build"))) {
  await $`mkdir build`;
}
cd("build");

// Build with emsdk
await $`emcmake cmake -G Ninja ..`;
await $`cmake --build . -j ${jobs}`;

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
await $`cmake ../../test`;
await $`cmake --build .`;
