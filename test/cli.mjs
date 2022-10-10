import { createRequire } from "module";
const require = createRequire(import.meta.url);
const { inject } = require("..");

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
        ["./dist/cli.js", filename, "foobar", resourceFilename],
        { encoding: "utf-8" }
      );
      // TODO(dsanders11) - Enable this once we squelch LIEF warnings
      // expect(stderr).to.be.empty;
      expect(stdout).to.be.empty;
      expect(status).to.equal(0);
    }

    // After injection
    {
      const { status, stdout } = spawnSync(filename, { encoding: "utf-8" });
      expect(status).to.equal(0);
      expect(stdout).to.have.string(resourceContents);
    }
  }).timeout(30000);
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
      await inject(filename, "foobar", resourceData);
    }

    // After injection
    {
      const { status, stdout } = spawnSync(filename, { encoding: "utf-8" });
      expect(status).to.equal(0);
      expect(stdout).to.have.string(resourceContents);
    }
  }).timeout(30000);
});

describe("Inject data into Node.js using CLI", () => {
  let filename;
  let tempDir;
  let resourceContents;
  let resourceFilename;

  beforeEach(async () => {
    tempDir = temporaryDirectory();
    await fs.ensureDir(tempDir);

    filename = path.join(tempDir, path.basename(process.execPath));

    await fs.copy(process.execPath, filename);

    resourceContents = crypto.randomBytes(64).toString("hex");
    resourceFilename = path.join(tempDir, "resource.bin");
    await fs.writeFile(resourceFilename, resourceContents);
  });

  afterEach(() => {
    rimraf.sync(tempDir);
  });

  it("should inject a resource successfully", async () => {
    {
      const { status, stdout, stderr } = spawnSync(
        "node",
        ["./dist/cli.js", filename, "foobar", resourceFilename],
        { encoding: "utf-8" }
      );
      // TODO(dsanders11) - Enable this once we squelch LIEF warnings
      // expect(stderr).to.be.empty;
      expect(stdout).to.be.empty;
      expect(status).to.equal(0);
    }

    // After injection
    {
      const { status } = spawnSync(filename, ["-e", "process.exit()"], {
        encoding: "utf-8",
      });
      expect(status).to.equal(0);
    }
  }).timeout(60000);
});

describe("Inject data into Node.js using API", () => {
  let filename;
  let tempDir;
  let resourceContents;
  let resourceFilename;

  beforeEach(async () => {
    tempDir = temporaryDirectory();
    await fs.ensureDir(tempDir);

    filename = path.join(tempDir, path.basename(process.execPath));

    await fs.copy(process.execPath, filename);

    resourceContents = crypto.randomBytes(64).toString("hex");
    resourceFilename = path.join(tempDir, "resource.bin");
    await fs.writeFile(resourceFilename, resourceContents);
  });

  afterEach(() => {
    rimraf.sync(tempDir);
  });

  it("should inject a resource successfully", async () => {
    {
      const resourceData = await fs.readFile(resourceFilename);
      await inject(filename, "foobar", resourceData);
    }

    // After injection
    {
      const { status } = spawnSync(filename, ["-e", "process.exit()"], {
        encoding: "utf-8",
      });
      expect(status).to.equal(0);
    }
  }).timeout(70000);
});
