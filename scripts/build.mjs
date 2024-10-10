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

// Bundle api.js and copy artifacts to dist
await fs.copy("../src/api.js", "api.js");
await $`esbuild api.js --bundle --platform=node --outfile=../dist/api.js`;
await fs.copy("../src/cli.js", "../dist/cli.js");
await fs.copy("../postject-api.h", "../dist/postject-api.h");

// Replace all occurrences of `__filename` and `__dirname` with "" because
// Node.js core doesn't support it. These uses are functionally dead when
// `SINGLE_FILE` is enabled anyways.
// Refs: https://github.com/postmanlabs/postject/issues/50
// TODO(RaisinTen): Send a PR to emsdk to get rid of these symbols from the
// affected code paths when `SINGLE_FILE` is enabled.
const contents = await fs.readFile("../dist/api.js", "utf-8");
const replaced = contents.replace(/\b__filename\b|\b__dirname\b/g, "''");
await fs.writeFile("../dist/api.js", replaced);

// Build tests
if (!(await fs.exists("./test"))) {
  await $`mkdir test`;
}

cd("test");
await $`cmake ../../test`;
await $`cmake --build .`;
