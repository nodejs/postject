#!/usr/bin/env zx

let target = argv.target;
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

async function build() {
  try {
    await which("emcmake");
  } catch {
    console.log("ERROR: Couldn't find `emcmake`, is emsdk installed?");
    process.exit(1);
  }

  // Create build folder if needed
  if (!(await fs.exists("./build"))) {
    await $`mkdir -p build`;
  }

  cd("build");

  // Build with emsdk
  await $`emcmake cmake -G Ninja ..`;
  await $`cmake --build . -j ${jobs}`;

  // Bundle api.js and copy artifacts to dist
  await fs.copy("../src/api.js", "api.js");
  await $`esbuild api.js --bundle --platform=node --outfile=../dist/api.js`;
  await fs.copy("../src/cli.js", "../dist/cli.js");
  await fs.copy("../postject-api.h", "../dist/postject-api.h");

  cd("..");
}

async function test() {
  // Create build folder if needed
  if (!(await fs.exists("./build/test"))) {
    await $`mkdir -p build/test`;
  }

  cd("build/test");

  await $`cmake ../../test`;
  await $`cmake --build .`;

  cd("../..");
}

switch (target) {
  case "build":
    await build();
    break;
  case "test":
    await test();
    break;
  default:
    await build();
    await test();
}
