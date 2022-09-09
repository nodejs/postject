import * as crypto from "crypto";

import { default as chai, expect } from "chai";
import chaiAsPromised from "chai-as-promised";
chai.use(chaiAsPromised);

import { temporaryFile } from "tempy";
import { $, fs } from "zx";

// TODO - More test coverage
describe("postject CLI", () => {
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
    const filename = temporaryFile();
    await fs.copy("./build/test/cpp_test", filename);

    const resourceFilename = temporaryFile();
    await fs.writeFile(
      resourceFilename,
      crypto.randomBytes(64).toString("hex")
    );

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
      expect(stdout).to.have.string("test");
    }
  }).timeout(6000);
});
