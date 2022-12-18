#!/usr/bin/env node

const { constants, promises: fs } = require("fs");
const path = require("path");
const { inject } = require("./api.js");
const { argumentParser } = require("./argsParser.js");

async function main(filename, resourceName, resource, options) {
  if (options.outputApiHeader) {
    // Handles --output-api-header.
    console.log(
      await fs.readFile(path.join(__dirname, "postject-api.h"), "utf-8")
    );
    process.exit();
  }

  let resourceData;

  try {
    await fs.access(resource, constants.R_OK);
    resourceData = await fs.readFile(resource);
  } catch {
    console.log("Can't read resource file");
    process.exit(1);
  }

  try {
    await inject(filename, resourceName, resourceData, {
      machoSegmentName: options.machoSegmentName,
      overwrite: options.overwrite,
    });
  } catch (err) {
    console.log(err.message);
    process.exit(1);
  }
}

if (require.main === module) {
  argumentParser(main);
}
