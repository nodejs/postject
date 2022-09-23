import { spawnSync } from "child_process";
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
    const { status, stdout } = spawnSync("node", ["./dist/main.js", "-h"], {
      encoding: "utf-8",
    });
    expect(status).to.equal(0);
    expect(stdout).to.have.string("Usage");
  });

  it("has required arguments", async () => {
    const { status, stderr } = spawnSync("node", ["./dist/main.js"], {
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
        ["./dist/main.js", filename, "foobar", resourceFilename],
        { encoding: "utf-8" }
      );
      expect(stderr).to.be.empty;
      expect(stdout).to.be.empty;
      expect(status).to.equal(0);
    }

    // After injection
    {
      const { status, stdout } = spawnSync(filename, { encoding: "utf-8" });
      expect(status).to.equal(0);
      expect(stdout).to.have.string(resourceContents);
    }
  }).timeout(8000);
});
