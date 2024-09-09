import { createRequire } from "module";
const require = createRequire(import.meta.url);
const { inject } = require("..");

import { spawnSync, execSync } from "child_process";
import * as crypto from "crypto";
import * as path from "path";
import * as os from "os";

import { default as chai, expect } from "chai";
import chaiAsPromised from "chai-as-promised";
chai.use(chaiAsPromised);

import fs from "fs-extra";
import rimraf from "rimraf";
import { temporaryDirectory } from "tempy";

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
    await fs.ensureDir(tempDir);

    if (IS_WINDOWS) {
      originalFilename = "./build/test/Debug/cpp_test.exe";
      filename = path.join(tempDir, "cpp_test.exe");
    } else {
      originalFilename = "./build/test/cpp_test";
      filename = path.join(tempDir, "cpp_test");
    }

    await fs.copy(originalFilename, filename);

    resourceContents = crypto.randomBytes(64).toString("hex");
    resourceFilename = path.join(tempDir, "resource.bin");
    await fs.writeFile(resourceFilename, resourceContents);
  });

  afterEach(() => {
    rimraf.sync(tempDir);
  });

  it("should have help output", async () => {
    const { status, stdout } = spawnSync("node", ["./dist/cli.js", "-h"], {
      encoding: "utf-8",
    });
    expect(status).to.equal(0);
    expect(stdout).to.have.string("Usage");
  });

  it("has required arguments", async () => {
    const { status, stderr } = spawnSync("node", ["./dist/cli.js"], {
      encoding: "utf-8",
    });
    expect(status).to.equal(1);
    expect(stderr).to.have.string("required");
  });

  it("should inject a resource successfully", async () => {
    // Before injection
    {
      const { status, stdout } = spawnSync(filename, { encoding: "utf-8" });
      expect(status).to.equal(0);
      expect(stdout).to.have.string("Hello world");
    }

    {
      const { status, stdout, stderr } = spawnSync(
        "node",
        [
          "./dist/cli.js",
          filename,
          "foobar",
          resourceFilename,
          "--sentinel-fuse",
          "NODE_JS_FUSE_fce680ab2cc467b6e072b8b5df1996b2",
        ],
        { encoding: "utf-8" }
      );
      // TODO(dsanders11) - Enable this once we squelch LIEF warnings
      // expect(stderr).to.be.empty;
      expect(stdout).to.have.string("Injection done!");
      expect(status).to.equal(0);
    }

    // Verifying code signing using a self-signed certificate.
    {
      if (process.platform === "darwin") {
        let codesignFound = false;
        try {
          execSync("command -v codesign");
          codesignFound = true;
        } catch (err) {
          console.log(err.message);
        }
        if (codesignFound) {
          execSync(`codesign --sign - ${filename}`);
          execSync(`codesign --verify ${filename}`);
        }
      }
      // TODO(RaisinTen): Test code signing on Windows.
    }

    // After injection
    {
      const { status, stdout } = spawnSync(filename, { encoding: "utf-8" });
      expect(status).to.equal(0);
      expect(stdout).to.have.string(resourceContents);
    }
  }).timeout(15_000);

  it("should display an error message when filename doesn't exist", async () => {
    {
      const { status, stdout, stderr } = spawnSync(
        "node",
        [
          "./dist/cli.js",
          "--verbose",
          "unknown-filename",
          "foobar",
          resourceFilename,
          "--sentinel-fuse",
          "NODE_JS_FUSE_fce680ab2cc467b6e072b8b5df1996b2",
        ],
        { encoding: "utf-8" }
      );
      expect(stdout).to.have.string(
        "Error: Can't read and write to target executable"
      );
      expect(stdout).to.have.string(
        "Error: ENOENT: no such file or directory"
      );
      expect(stdout).to.not.have.string("Injection done!");
      expect(status).to.equal(1);
    }
  }).timeout(15_000);

  it("should display an error message when the file is not a supported executable type", async () => {
    const bogusFile = path.join(tempDir, "bogus.exe");
    await fs.writeFile(bogusFile, "#!/bin/bash");

    const { status, stdout } = spawnSync(
      "node",
      [
        "./dist/cli.js",
        bogusFile,
        "foobar",
        resourceFilename,
        "--sentinel-fuse",
        "NODE_JS_FUSE_fce680ab2cc467b6e072b8b5df1996b2",
      ],
      { encoding: "utf-8" }
    );
    expect(stdout).to.have.string(
      "Error: Executable must be a supported format: ELF, PE, or Mach-O"
    );
    expect(stdout).to.not.have.string("Injection done!");
    expect(status).to.equal(1);
  }).timeout(15_000);
});

describe("postject API", () => {
  let filename;
  let tempDir;
  let resourceContents;
  let resourceFilename;
  const IS_WINDOWS = os.platform() === "win32";

  beforeEach(async () => {
    let originalFilename;

    tempDir = temporaryDirectory();
    await fs.ensureDir(tempDir);

    if (IS_WINDOWS) {
      originalFilename = "./build/test/Debug/cpp_test.exe";
      filename = path.join(tempDir, "cpp_test.exe");
    } else {
      originalFilename = "./build/test/cpp_test";
      filename = path.join(tempDir, "cpp_test");
    }

    await fs.copy(originalFilename, filename);

    resourceContents = crypto.randomBytes(64).toString("hex");
    resourceFilename = path.join(tempDir, "resource.bin");
    await fs.writeFile(resourceFilename, resourceContents);
  });

  afterEach(() => {
    rimraf.sync(tempDir);
  });

  it("should inject a resource successfully", async () => {
    // Before injection
    {
      const { status, stdout } = spawnSync(filename, { encoding: "utf-8" });
      expect(status).to.equal(0);
      expect(stdout).to.have.string("Hello world");
    }

    {
      const resourceData = await fs.readFile(resourceFilename);
      await inject(filename, "foobar", resourceData, {
        sentinelFuse: "NODE_JS_FUSE_fce680ab2cc467b6e072b8b5df1996b2",
      });
    }

    // Verifying code signing using a self-signed certificate.
    {
      if (process.platform === "darwin") {
        let codesignFound = false;
        try {
          execSync("command -v codesign");
          codesignFound = true;
        } catch (err) {
          console.log(err.message);
        }
        if (codesignFound) {
          execSync(`codesign --sign - ${filename}`);
          execSync(`codesign --verify ${filename}`);
        }
      }
      // TODO(RaisinTen): Test code signing on Windows.
    }

    // After injection
    {
      const { status, stdout } = spawnSync(filename, { encoding: "utf-8" });
      expect(status).to.equal(0);
      expect(stdout).to.have.string(resourceContents);
    }
  }).timeout(15_000);
});

describe("api.js should not contain __filename and __dirname", () => {
  let contents;

  before(async () => {
    contents = await fs.readFile("./dist/api.js", "utf-8");
  });

  it("should not contain __filename", () => {
    expect(contents).to.not.have.string("__filename");
  });

  it("should not contain __dirname", () => {
    expect(contents).to.not.have.string("__dirname");
  });
});
