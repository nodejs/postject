import * as crypto from "crypto";
import { promises as fs } from "fs";
import * as path from "path";
import * as os from "os";

import { default as chai, expect } from "chai";
import chaiAsPromised from "chai-as-promised";
chai.use(chaiAsPromised);

import rimraf from "rimraf";
import { temporaryDirectory } from "tempy";
import { $ } from "zx";

// TODO - More test coverage
describe("postject CLI", () => {
  let filename;
  let tempDir;
  let resourceContents;
  let resourceFilename;
  const IS_WINDOWS = os.platform() === "win32";

  beforeEach(async () => {
    let originalFilename;

    tempDir = temporaryDirectory();

    if (IS_WINDOWS) {
      originalFilename = "./build/test/Debug/cpp_test.exe";
      filename = path.join(tempDir, "cpp_test.exe");
    } else {
      originalFilename = "./build/test/cpp_test";
      filename = path.join(tempDir, "cpp_test");
    }

    await fs.copyFile(originalFilename, filename);

    resourceContents = crypto.randomBytes(64).toString("hex");
    resourceFilename = path.join(tempDir, "resource.bin");
    await fs.writeFile(resourceFilename, resourceContents);
  });

  afterEach(() => {
    rimraf.sync(tempDir);
  });

  it("should have help output", async () => {
    const { exitCode, stdout } = await $`node ./dist/main.js -h`;
    expect(exitCode).to.equal(0);
    expect(stdout).to.have.string("Usage");
  });

  it("has required arguments", async () => {
    try {
      await $`node ./dist/main.js`;
      expect.fail("Should have thrown an error");
    } catch ({ exitCode, stderr }) {
      expect(exitCode).to.equal(1);
      expect(stderr).to.have.string("required");
    }
  });

  it("should inject a resource successfully", async () => {
    // Before injection
    {
      const { exitCode, stdout } = await $`${filename}`;
      expect(exitCode).to.equal(0);
      expect(stdout).to.have.string("Hello world");
    }

    {
      const { exitCode } =
        await $`node ./dist/main.js ${filename} foobar ${resourceFilename}`;
      expect(exitCode).to.equal(0);
    }

    // After injection
    {
      const { exitCode, stdout } = await $`${filename}`;
      expect(exitCode).to.equal(0);
      expect(stdout).to.have.string(resourceContents);
    }
  }).timeout(8000);
});
